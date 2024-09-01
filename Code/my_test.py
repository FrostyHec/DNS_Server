from local_dns_server import *
import unittest

from test import read_bytes_from_file


class TestStaticFunc(unittest.TestCase):
    def test_encode_and_decode(self):
        b, i, d = encode_dns_name('baidu.com', 0, {})
        b2, i2, d = encode_dns_name('www.baidu.com', i, d)
        b += b2
        str, _ = parse_dns_name(b, i)
        assert str == 'www.baidu.com'

    def test_ipv6_shorten(self):
        assert shorten_ipv6("0:0:0:0:0:0:0:0") == '::'
        assert shorten_ipv6("0:0:0:0:1:0:0:1") == '::1:0:0:1'
        assert shorten_ipv6("0:0:0:0:1:0:0:0") == '::1:0:0:0'
        assert shorten_ipv6("1:0:0:0:1:0:0:0") == '1::1:0:0:0' or shorten_ipv6("1:0:0:0:1:0:0:0") == '1:0:0:0:1::'
        assert shorten_ipv6("1:0:0:0:1:1:1:0") == '1::1:1:1:0'
        assert shorten_ipv6("1:1:1:1:1:0:0:0") == '1:1:1:1:1::'
        assert shorten_ipv6("1:0:0:0:1:0:0:114") == '1::1:0:0:114'

    def test_ipv6_extend(self):
        assert extend_ipv6('1::1') == '1:0:0:0:0:0:0:1'
        assert extend_ipv6('::') == '0:0:0:0:0:0:0:0'
        assert extend_ipv6('1::') == '1:0:0:0:0:0:0:0'
        assert extend_ipv6('::1') == '0:0:0:0:0:0:0:1'
        assert extend_ipv6('1::1:0:0:0') == '1:0:0:0:1:0:0:0'
        assert extend_ipv6('1:0:0:0:1::') == '1:0:0:0:1:0:0:0'
        assert extend_ipv6('1:1:1:1:1::') == '1:1:1:1:1:0:0:0'
        assert extend_ipv6('1::1:0:0:114') == '1:0:0:0:1:0:0:114'

    def test_message(self):
        dns_response_bytes = read_bytes_from_file('./raw_packet/dns_response.raw')
        msg = DNSMessage.from_wire(dns_response_bytes)
        b = msg.encode_bytes()
        msg2 = DNSMessage.from_wire(b)
        assert msg == msg2