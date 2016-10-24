import re
import pkg_resources
import inspect

tld_names = pkg_resources.resource_string('domainfuzzer.data',
                                          'effective_tld_names.dat')


def is_valid(domain=None):
    drex = (r'^(?=.{4,255}$)([a-zA-Z0-9][a-zA-Z0-9-]{,61}[a-zA-Z0-9]\.)+'
            r'[a-zA-Z0-9]{2,5}$')
    return re.match(drex, domain)


def sorted_attrs(class_):
    attrs = inspect.getmembers(class_, lambda a: not (inspect.isroutine(a)))
    _sorted_attrs = [a for a in attrs if not
                     (a[0].startswith('__') and a[0].endswith('__'))]
    return _sorted_attrs


class Domain:
    fuzzer = None
    name = None
    dns_a = None
    dns_aaaa = None
    dns_ns = None
    dns_mx = None
    mx_spy = None
    whois_created = None
    whois_updated = None
    geoip_country = None
    geoip_cc = None
    ssdeep_score = None
    http_banner = None
    smtp_banner = None

    def __init__(self, name, fuzzer):
        self.name = name
        self.fuzzer = fuzzer

    def __repr__(self):
        fmt = "{}('{}', '{}')"
        return fmt.format(self.__class__.__name__, self.name, self.fuzzer)

    def any(self, keys):
        if isinstance(keys, str):
            keys = [keys]
        return any(k in keys for k in self.__dict__.keys())


class DomainFuzz:

    def __init__(self, domain):
        self.domain, self.tld = self._domain_tld(domain)
        self.domains = []
        self.fuzzers = ('addition', 'bitsquatting', 'homoglyph', 'hyphenation',
                        'insertion', 'omission', 'repetition', 'replacement',
                        'subdomain', 'transposition', 'various')

        self.qwerty = {
            '1': '2q', '2': '3wq1', '3': '4ew2', '4': '5re3', '5': '6tr4',
            '6': '7yt5', '7': '8uy6', '8': '9iu7', '9': '0oi8', '0': 'po9',
            'q': '12wa', 'w': '3esaq2', 'e': '4rdsw3', 'r': '5tfde4',
            't': '6ygfr5', 'y': '7uhgt6', 'u': '8ijhy7', 'i': '9okju8',
            'o': '0plki9', 'p': 'lo0',
            'a': 'qwsz', 's': 'edxzaw', 'd': 'rfcxse', 'f': 'tgvcdr',
            'g': 'yhbvft', 'h': 'ujnbgy', 'j': 'ikmnhu', 'k': 'olmji',
            'l': 'kop',
            'z': 'asx', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn',
            'n': 'bhjm', 'm': 'njk'
        }
        self.qwertz = {
            '1': '2q', '2': '3wq1', '3': '4ew2', '4': '5re3', '5': '6tr4',
            '6': '7zt5', '7': '8uz6', '8': '9iu7', '9': '0oi8', '0': 'po9',
            'q': '12wa', 'w': '3esaq2', 'e': '4rdsw3', 'r': '5tfde4',
            't': '6zgfr5', 'z': '7uhgt6', 'u': '8ijhz7', 'i': '9okju8',
            'o': '0plki9', 'p': 'lo0',
            'a': 'qwsy', 's': 'edxyaw', 'd': 'rfcxse', 'f': 'tgvcdr',
            'g': 'zhbvft', 'h': 'ujnbgz', 'j': 'ikmnhu', 'k': 'olmji',
            'l': 'kop',
            'y': 'asx', 'x': 'ysdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn',
            'n': 'bhjm', 'm': 'njk'
        }
        self.azerty = {
            '1': '2a', '2': '3za1', '3': '4ez2', '4': '5re3', '5': '6tr4',
            '6': '7yt5', '7': '8uy6', '8': '9iu7', '9': '0oi8', '0': 'po9',
            'a': '2zq1', 'z': '3esqa2', 'e': '4rdsz3', 'r': '5tfde4',
            't': '6ygfr5', 'y': '7uhgt6', 'u': '8ijhy7', 'i': '9okju8',
            'o': '0plki9', 'p': 'lo0m',
            'q': 'zswa', 's': 'edxwqz', 'd': 'rfcxse', 'f': 'tgvcdr',
            'g': 'yhbvft', 'h': 'ujnbgy', 'j': 'iknhu', 'k': 'olji',
            'l': 'kopm', 'm': 'lp',
            'w': 'sxq', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn',
            'n': 'bhj'
        }
        self.keyboards = [self.qwerty, self.qwertz, self.azerty]

    def _domain_tld(self, domain):
        domain = domain.rsplit('.', 2)

        if len(domain) == 2:
            return domain[0], domain[1]

        cc_tld = {}
        re_tld = re.compile('^[a-z]{2,4}\.[a-z]{2}$', re.IGNORECASE)

        for line in tld_names.decode('utf-8').splitlines():
            line = line[:-1]
            if re_tld.match(line):
                sld, tld = line.split('.')
                if tld not in cc_tld:
                    cc_tld[tld] = []
                cc_tld[tld].append(sld)

        sld_tld = cc_tld.get(domain[2])
        if sld_tld:
            if domain[1] in sld_tld:
                return domain[0], domain[1] + '.' + domain[2]

        return domain[0] + '.' + domain[1], domain[2]

    def _filter_domains(self):
        seen = set()
        filtered = []

        for d in self.domains:
            if is_valid(d.name) and d.name not in seen:
                seen.add(d.name)
                filtered.append(d)

        self.domains = filtered

    def _bitsquatting(self):
        result = []
        masks = [1, 2, 4, 8, 16, 32, 64, 128]
        for i in range(0, len(self.domain)):
            c = self.domain[i]
            for j in range(0, len(masks)):
                b = chr(ord(c) ^ masks[j])
                o = ord(b)
                if (48 <= o <= 57) or (97 <= o <= 122) or o == 45:
                    result.append(self.domain[:i] + b + self.domain[i + 1:])

        return result

    def _homoglyph(self):
        glyphs = {
            'd': ['b', 'cl', 'dl', 'di'], 'm': ['n', 'nn', 'rn', 'rr'],
            'l': ['1', 'i'],
            'o': ['0'], 'k': ['lk', 'ik', 'lc'], 'h': ['lh', 'ih'],
            'w': ['vv'],
            'n': ['m', 'r'], 'b': ['d', 'lb', 'ib'], 'i': ['1', 'l'],
            'g': ['q'], 'q': ['g']
        }
        result = []

        for ws in range(0, len(self.domain)):
            for i in range(0, (len(self.domain) - ws) + 1):
                win = self.domain[i:i + ws]

                j = 0
                while j < ws:
                    c = win[j]
                    if c in glyphs:
                        win_copy = win
                        for g in glyphs[c]:
                            win = win.replace(c, g)
                            result.append(
                                self.domain[:i] + win + self.domain[i + ws:])
                            win = win_copy
                    j += 1

        return list(set(result))

    def _hyphenation(self):
        result = []

        for i in range(1, len(self.domain)):
            if self.domain[i] not in ['-', '.'] and \
                            self.domain[i - 1] not in ['-', '.']:
                result.append(self.domain[:i] + '-' + self.domain[i:])

        return result

    def _insertion(self):
        result = []

        for i in range(1, len(self.domain) - 1):
            for keys in self.keyboards:
                if self.domain[i] in keys:
                    for c in keys[self.domain[i]]:
                        result.append(
                            self.domain[:i] + c + self.domain[i] +
                            self.domain[i + 1:])
                        result.append(
                            self.domain[:i] + self.domain[i] + c +
                            self.domain[i + 1:])

        return list(set(result))

    def _omission(self):
        result = []

        for i in range(0, len(self.domain)):
            result.append(self.domain[:i] + self.domain[i + 1:])

        n = re.sub(r'(.)\1+', r'\1', self.domain)

        if n not in result and n != self.domain:
            result.append(n)

        return list(set(result))

    def _repetition(self):
        result = []

        for i in range(0, len(self.domain)):
            if self.domain[i].isalpha():
                result.append(self.domain[:i] + self.domain[i] + self.domain[
                    i] + self.domain[i + 1:])

        return list(set(result))

    def _replacement(self):
        result = []

        for i in range(0, len(self.domain)):
            for keys in self.keyboards:
                if self.domain[i] in keys:
                    for c in keys[self.domain[i]]:
                        result.append(
                            self.domain[:i] + c + self.domain[i + 1:])

        return list(set(result))

    def _subdomain(self):
        result = []

        for i in range(1, len(self.domain)):
            if self.domain[i] not in ['-', '.'] and \
                            self.domain[i - 1] not in ['-', '.']:
                result.append(self.domain[:i] + '.' + self.domain[i:])

        return result

    def _transposition(self):
        result = []

        for i in range(0, len(self.domain) - 1):
            if self.domain[i + 1] != self.domain[i]:
                result.append(
                    self.domain[:i] + self.domain[i + 1] + self.domain[
                        i] + self.domain[i + 2:])

        return result

    def _addition(self):
        result = []

        for i in range(97, 123):
            result.append(self.domain + chr(i))

        return result

    def _various(self):
        result = []
        if not self.domain.startswith('www.'):
            result.append('ww' + self.domain)
            result.append('www' + self.domain)
            result.append('www-' + self.domain)
        return result

    def generate(self):
        self.domains.append(
            Domain(fuzzer='Original*',
                   name='{}.{}'.format(self.domain, self.tld))
        )
        for fuzzer_name in self.fuzzers:
            fuzzed = getattr(self, '_'+fuzzer_name)()
            for domain in fuzzed:
                self.domains.append(
                    Domain(fuzzer=fuzzer_name.title(),
                           name='{}.{}'.format(domain, self.tld))
                )

        if '.' in self.tld:
            self.domains.append(
                Domain(fuzzer='Various',
                       name='{}.{}'.format(self.domain,
                                           self.tld.split('.')[-1]))
            )
            self.domains.append(
                Domain(fuzzer='Various',
                       name='{}.{}'.format(self.domain, self.tld))
            )
        if '.' not in self.tld:
            self.domains.append(
                Domain(fuzzer='Various',
                       name='{}.{}.{}'.format(self.domain, self.tld, self.tld))
            )
        if self.tld != 'com' and '.' not in self.tld:
            self.domains.append(
                Domain(fuzzer='Various',
                       name='{}-{}.com'.format(self.domain, self.tld))
            )

        self._filter_domains()


class DomainDict(DomainFuzz):
    def __init__(self, domain):
        super().__init__(domain=domain)
        self.dictionary = []

    def load_dict(self, file):
        with open(file) as f:
            for word in f:
                word = word.strip('\n')
                if word.isalpha() and word not in self.dictionary:
                    self.dictionary.append(word)

    def __dictionary(self):
        result = []

        domain = self.domain.rsplit('.', 1)
        if len(domain) > 1:
            prefix = domain[0] + '.'
            name = domain[1]
        else:
            prefix = ''
            name = domain[0]

        for word in self.dictionary:
            result.append(prefix + name + '-' + word)
            result.append(prefix + name + word)
            result.append(prefix + word + '-' + name)
            result.append(prefix + word + name)

        return result

    def generate(self):
        for domain in self.__dictionary():
            self.domains.append(
                Domain(fuzzer='Dictionary',
                       name='{}.{}'.format(domain, self.tld))
            )
