import io
import socket
from unittest.mock import mock_open, patch, MagicMock
from urllib.parse import urlparse

import pytest
from dns.resolver import Answer
from domainfuzzer.augment import Augmenter
from domainfuzzer.domain import DomainFuzz, DomainDict


@pytest.fixture
def dictfile():
    dict = io.StringIO("auth\nlogin\ntest\n")
    return dict


@pytest.fixture
def domain():
    d = DomainFuzz('google.co.uk')
    d.generate()
    return d


@pytest.fixture
def url():
    return urlparse('http://google.co.uk')


@pytest.fixture
def augments():
    return {'banners': True,
            'mxcheck': True,
            'whois': True,
            'geoip': True,
            'ssdeep': True}


def fake_answer():
    answer = MagicMock(spec=Answer)
    mx = MagicMock(
        exchange='mail.google.com.'
    )
    answer.side_effect = [
        ['ns3.google.com. dns-admin.google.com. 137002938 900 900 1800 60'],
        ['216.58.210.35'],
        ['2a00:1450:4009:800::200'],
        [mx]
    ]
    return answer


def fake_smtp():
    smtp = MagicMock('smtplib.SMTP')
    smtp.return_value.sendmail.return_value = MagicMock('smtp_connection')
    return smtp


def fake_sock():
    sock = MagicMock(spec=socket.socket)
    sock.return_value.recv.return_value = \
        bytes('HTTP/1.1 301 Moved Permanently\r\n'
              'Location: http://www.google.co.uk/\r\n'
              'Content-Type: text/html; charset=UTF-8\r\n'
              'Server: gws\r\nContent-Length: 221\r\n',
              'utf-8')
    return sock


def fake_urlopen():
    urlopen = MagicMock()
    urlopen.return_value.read.return_value = bytes('resource content', 'utf-8')
    return urlopen


def test_fuzz_domains(domain):
    assert(len(domain.domains) > 0)


def test_fuzz_domains_dict(url):
    with patch('builtins.open', mock_open()) as m:
        m.return_value = io.StringIO("auth\nlogin\ntest\n")

        ddict = DomainDict(url.netloc)
        ddict.load_dict('/dummy/path')
        ddict.generate()

        m.assert_called_once_with('/dummy/path')
        assert (len(ddict.domains) > 0)


def test_augmenter(domain, url, augments):
    with patch('dns.resolver.Resolver.query', fake_answer()), \
            patch('smtplib.SMTP', fake_smtp()) as smtp, \
            patch('domainfuzzer.augment.socket.socket', fake_sock()), \
            patch('urllib.request.urlopen', fake_urlopen()):
        test_domain = domain.domains[1]
        assert test_domain.name == 'google.coa.uk'

        test_domain._original_ctph = '3:mMRALR:mH'

        augmenter = Augmenter(test_domain, url, **augments)
        result = augmenter.augment()
        assert result.dns_a == '216.58.210.35'
        assert result.dns_ns == 'ns3.google.com'
        assert result.dns_mx == 'mail.google.com'
        smtp.assert_called_with(result.dns_mx, 25, timeout=1)
        assert result.http_banner == 'gws'
        assert result.smtp_banner == 'HTTP/1.1 301 Moved Permanently'
        assert test_domain.ctph == '3:mMRALR:mH' and \
            test_domain.ssdeep_score == 100
