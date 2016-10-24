import GeoIP
import logging
import smtplib
import socket
from urllib import request
from urllib.parse import urlunparse

import dns.resolver
import pkg_resources
import ssdeep
import whois
from domainfuzzer import random_str

GeoIPDB = pkg_resources.resource_filename('domainfuzzer.data', 'GeoIP.dat')
logging.getLogger(__name__).addHandler(logging.NullHandler())


class Augmenter:

    def __init__(self, domain, original_url, **kwargs):
        self._ua = kwargs.get('useragent', 'Mozilla/5.0')
        self.original_url = original_url
        self.original_domain = original_url.netloc or original_url.path
        self.domain = domain
        self.augments = [k for k, v in kwargs.items() if
                         v and hasattr(self, k)]
        self._dns()

    def augment(self):
        for a in self.augments:
            logging.debug('Running {} augmenter for {}'.format(a, self.domain))
            getattr(self, a)()
        return self.domain

    def banners(self):
        if self.domain.dns_a:
            banner = self._banner_http(self.domain.dns_a, self.domain.name)
            if banner:
                self.domain.http_banner = banner
        if self.domain.dns_mx:
            banner = self._banner_smtp(self.domain.dns_mx)
            if banner:
                self.domain.smtp_banner = banner

    def _banner_http(self, ip, vhost):
        try:
            http = socket.socket()
            http.settimeout(1)
            http.connect((ip, 80))

            head = ('HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: '
                    '%s\r\n\r\n' % (str(vhost), self._ua))
            http.send(bytes(head, 'utf-8'))
            response = http.recv(1024).decode('utf-8')
            http.close()
        except Exception as e:
            print(e)
            pass
        else:
            sep = '\r\n' if '\r\n' in response else '\n'
            headers = response.split(sep)
            for field in headers:
                if field.startswith('Server: '):
                    return field[8:]
            banner = headers[0].split(' ')
            if len(banner) > 1:
                return 'HTTP %s' % banner[1]

    def _banner_smtp(self, mx):
        try:
            smtp = socket.socket()
            smtp.settimeout(1)
            smtp.connect((mx, 25))
            response = smtp.recv(1024).decode('utf-8')
            smtp.close()
        except Exception:
            pass
        else:
            sep = '\r\n' if '\r\n' in response else '\n'
            hello = response.split(sep)[0]
            if hello.startswith('220'):
                return hello[4:].strip()
            return hello[:40]

    def _dns(self):
        resolv = dns.resolver.Resolver()
        resolv.lifetime = 3
        resolv.timeout = 1

        try:
            ans = resolv.query(self.domain.name, 'SOA')
            self.domain.dns_ns = str(sorted(ans)[0]).split(' ')[0][:-1].lower()
        except Exception:
            pass

        if self.domain.dns_ns:
            try:
                ans = resolv.query(self.domain.name, 'A')
                self.domain.dns_a = str(sorted(ans)[0])
            except Exception:
                pass

            try:
                ans = resolv.query(self.domain.name, 'AAAA')
                self.domain.dns_aaaa = str(sorted(ans)[0])
            except Exception:
                pass

            try:
                ans = resolv.query(self.domain.name, 'MX')
                mx = str(sorted(ans)[0].exchange)[:-1].lower()
                if mx:
                    self.domain.dns_mx = mx
            except Exception:
                pass

        if not self.domain.any(['dns_a', 'dns_aaaa']):
            try:
                ip = socket.getaddrinfo(self.domain.name, 80)
            except Exception:
                pass
            else:
                for j in ip:
                    if '.' in j[4][0]:
                        self.domain.dns_a = j[4][0]
                        break
                for j in ip:
                    if ':' in j[4][0]:
                        self.domain.dns_aaaa = j[4][0]
                        break

    def mxcheck(self):
        if self.domain.dns_mx:
            if self.domain.name is not self.original_domain:
                if self._can_mail(self.domain.dns_mx, self.original_domain,
                                  self.domain.name):
                    self.domain.mx_spy = True

    def _can_mail(self, mx, from_domain, to_domain):
        from_addr = '{}@{}'.format(random_str(), from_domain)
        to_addr = '{}@{}'.format(random_str(), to_domain)
        try:
            smtp = smtplib.SMTP(mx, 25, timeout=1)
            smtp.sendmail(from_addr, to_addr, 'Boom baby!')
            smtp.quit()
        except Exception as e:
            return False
        else:
            return True

    def whois(self):
        if self.domain.any(['dns_a', 'dns_ns']):
            try:
                whoisdb = whois.query(self.domain.name)
                self.domain.whois_created = str(
                    whoisdb.creation_date).replace(' ', 'T')
                self.domain.whois_updated = str(
                    whoisdb.last_updated).replace(' ', 'T')
            except Exception:
                pass

    def geoip(self):
        if self.domain.any('dns_a'):
            gi = GeoIP.open(GeoIPDB,
                            GeoIP.GEOIP_INDEX_CACHE | GeoIP.GEOIP_CHECK_CACHE)
            try:
                country = gi.country_name_by_addr(self.domain.dns_a)
                cc = gi.country_code_by_addr(self.domain.dns_a)
            except TypeError as te:
                logging.error(te)
            else:
                if country:
                    self.domain.geoip_country = country.split(',')[0]
                    self.domain.geoip_cc = cc

    def ssdeep(self):
        if self.domain.dns_a and hasattr(self.domain, '_original_ctph') and \
                self.original_url:
            ourl = self.original_url
            fuzzed_parts = (ourl.scheme, self.domain.name, ourl.path,
                            ourl.params, ourl.query, ourl.fragment)
            fuzzed_url = urlunparse(fuzzed_parts)
            req = request.Request(fuzzed_url)
            req.add_header('User-Agent', self._ua)
            try:
                resp = request.urlopen(req, timeout=5)
                ctph = ssdeep.hash(resp.read().decode())
            except Exception as ue:
                fmt = 'Could not calculate CTPH for {} ({})'
                logging.error(fmt.format(fuzzed_url, ue))
            else:
                self.domain.ctph = ctph
                self.domain.ssdeep_score = ssdeep.compare(
                    self.domain._original_ctph, ctph)
                del self.domain._original_ctph
