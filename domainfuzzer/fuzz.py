import argparse
import csv
import json
import logging
import os
import sys
from urllib import request
from urllib.error import URLError
from concurrent.futures import ProcessPoolExecutor, as_completed
from urllib.parse import urlparse
import ssdeep

from domainfuzzer.augment import Augmenter
from domainfuzzer.domain import DomainFuzz, DomainDict, sorted_attrs
from tqdm import tqdm


def generate_csv(domains):
    yield ([k for k, v in sorted_attrs(domains[0])])
    for domain in domains:
        yield([v or '' for k, v in sorted_attrs(domain)])


def enhance(domain, original_url, kwargs):
    # checks = [k for k, v in vars(kwargs).items()
    #           if v and hasattr(Augmenter, k)]
    augmenter = Augmenter(domain, original_url, **kwargs)
    return augmenter.augment()


def main(argv=None):
    if argv is None:
        argv = sys.argv

    parser = argparse.ArgumentParser(
        add_help=True,
        description='Fuzz domains to detect possible typosquatters, '
                    'phishing attacks, etc.'
    )

    parser.add_argument('domain', help='domain name or URL to check')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-c', '--csv', action='store_true',
                       help='output in CSV format')
    group.add_argument('-j', '--json', action='store_true',
                       help='output in JSON format')
    parser.add_argument('-r', '--registered', action='store_true',
                        help='show only registered domain names')
    parser.add_argument('-w', '--whois', action='store_true',
                        help='perform whois lookup')
    parser.add_argument('-g', '--geoip', action='store_true',
                        help='perform lookup for GeoIP location')
    parser.add_argument('-b', '--banners', action='store_true',
                        help='determine HTTP and SMTP service banners')
    parser.add_argument('-s', '--ssdeep', action='store_true',
                        help='fetch web pages and compare their fuzzy hashes '
                             'to evaluate similarity')
    parser.add_argument('-m', '--mxcheck', action='store_true',
                        help='check if MX host can be used to intercept '
                             'e-mails')
    parser.add_argument('-d', '--dictionary', type=str, metavar='FILE',
                        help='generate additional domains using dictionary '
                             'FILE')
    parser.add_argument('-t', '--workers', type=int, metavar='NUMBER',
                        default=os.cpu_count(),
                        help='start at most NUMBER of workers (default: {})'.
                        format(os.cpu_count()))
    parser.add_argument('-u', '--useragent', type=str,
                        default='Mozilla/5.0',
                        help="User-agent to use for HTTP requests")

    if len(sys.argv) < 2:
        parser.print_help()
        return 2

    log = logging.getLogger()
    log.addHandler(logging.StreamHandler())
    log.setLevel(logging.INFO)

    args = parser.parse_args(argv[1:])
    if '://' not in args.domain:
        # no scheme, assuming http
        args.domain = 'http://' + args.domain

    try:
        url = urlparse(args.domain)
    except Exception as err:
        return 1

    original_domain = url.netloc

    dfuzz = DomainFuzz(original_domain)
    dfuzz.generate()
    domains = dfuzz.domains

    if args.dictionary:
        log.info('[+] Adding dictionary entries...')
        ddict = DomainDict(original_domain)
        ddict.load_dict(args.dictionary)
        ddict.generate()
        domains += ddict.domains

    log.info('[+] {} domains for {}'.format(len(domains), original_domain))

    if args.ssdeep:
        log.info('[*] Calculating CTPH for {}'.format(url.geturl()))
        req = request.Request(url.geturl())
        req.add_header('User-Agent', args.useragent)
        try:
            resp = request.urlopen(req, timeout=5)
            original_ctph = ssdeep.hash(resp.read().decode())
        except URLError as ue:
            log.error('Could not calculcate original CTPH ({})'.format(ue))
        else:
            for d in domains:
                d._original_ctph = original_ctph

    results = []

    log.info('[+] Doing augmentation with {} workers...'.format(args.workers))
    _args = vars(args)
    _args.pop('domain')
    with ProcessPoolExecutor(max_workers=args.workers) as executor:
        futures = [executor.submit(enhance, d, url, _args)
                   for d in domains]
        kwargs = {
            'total': len(futures),
            'unit': 'domains',
            'unit_scale': True,
            'leave': True
        }
        for f in tqdm(as_completed(futures), **kwargs):
            results.append(f.result())

    if args.registered:
        log.info('[*] Using only registered domains')
        domains_registered = []
        for d in results:
            if d.any(['dns_a', 'dns_ns']):
                domains_registered.append(d)
        results = domains_registered
        del domains_registered

    if args.csv:
        log.info('[*] Outputting CSV...')
        out = csv.writer(sys.stdout)
        out.writerows(generate_csv(results))
    elif args.json:
        log.info('[*] Outputting JSON ...')
        sys.stdout.write(json.dumps([r.__dict__ for r in results],
                                    sort_keys=True))
    else:
        row_fmt = "{:<15}{:<40}{:<16}{:<5}{}"
        header = ['Algorithm', 'Domain', 'A', 'CC', 'NS']
        print('\033[1m', row_fmt.format(*header))
        print('=' * 80, '\033[0m')
        for d in results:
            print(row_fmt.format(d.fuzzer, d.name, str(d.dns_a),
                                 str(d.geoip_cc), str(d.dns_ns)))

if __name__ == '__main__':
    sys.exit(main())
