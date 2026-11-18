"""核心逻辑自测（不依赖 GUI，也不依赖真实网卡）。

运行：``python -m unittest discover -s tests -v``
"""

from __future__ import annotations

import os
import struct
import tempfile
import unittest

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from app.core.dissector import build_tree, dissect, tcp_flags_text
from app.core.filter_engine import DisplayFilter, FilterSyntaxError, validate
from app.core.flows import FlowRegistry
from app.core.pcap_io import load_pcap, save_pcap
from app.core.protocols import parse_http, parse_tls_client_hello
from app.core.stats import StatsCollector

CLIENT_MAC = "aa:bb:cc:dd:ee:ff"
SERVER_MAC = "11:22:33:44:55:66"


def eth():
    """显式指定 MAC，避免 Scapy 去解析本机缺省网卡。"""
    return Ether(src=CLIENT_MAC, dst=SERVER_MAC)


def tls_client_hello(sni: str) -> bytes:
    host = sni.encode()
    name_list = b"\x00" + struct.pack(">H", len(host)) + host
    ext_data = struct.pack(">H", len(name_list)) + name_list
    ext = b"\x00\x00" + struct.pack(">H", len(ext_data)) + ext_data
    body = (b"\x03\x03" + b"\x5a" * 32 + b"\x00" + b"\x00\x02\x13\x01"
            + b"\x01\x00" + struct.pack(">H", len(ext)) + ext)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


class DissectorTest(unittest.TestCase):
    def test_arp(self):
        pkt = Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=1, hwsrc=CLIENT_MAC, hwdst="00:00:00:00:00:00",
            psrc="192.168.1.10", pdst="192.168.1.1"
        )
        rec = dissect(bytes(pkt), 1700000000.0, 1)
        self.assertEqual(rec.proto, "ARP")
        self.assertIn("Who has 192.168.1.1", rec.info)
        self.assertIn("arp", rec.layers)

    def test_icmp(self):
        pkt = eth() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(type=8, id=1, seq=2)
        rec = dissect(bytes(pkt), 1700000000.0, 1)
        self.assertEqual(rec.proto, "ICMP")
        self.assertIn("Echo (ping) request", rec.info)

    def test_dns(self):
        pkt = (eth() / IP(src="192.168.1.10", dst="8.8.8.8")
               / UDP(sport=51000, dport=53) / DNS(id=0x1234, rd=1, qd=DNSQR(qname="www.ucas.ac.cn")))
        rec = dissect(bytes(pkt), 1700000000.0, 1)
        self.assertEqual(rec.proto, "DNS")
        self.assertIn("www.ucas.ac.cn", rec.info)
        self.assertEqual(rec.app["dns"]["qname"], "www.ucas.ac.cn")

    def test_http_request(self):
        payload = (b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n"
                   b"User-Agent: NetScope/1.0\r\n\r\n")
        pkt = eth() / IP(src="192.168.1.10", dst="93.184.216.34") / TCP(
            sport=40000, dport=80, flags="PA", seq=100) / Raw(payload)
        rec = dissect(bytes(pkt), 1700000000.0, 1)
        self.assertEqual(rec.proto, "HTTP")
        self.assertIn("GET /index.html", rec.info)
        self.assertEqual(rec.app["http"]["header_map"]["host"], "example.com")

    def test_tls_sni(self):
        pkt = eth() / IP(src="192.168.1.10", dst="93.184.216.34") / TCP(
            sport=40001, dport=443, flags="PA", seq=1) / Raw(tls_client_hello("www.github.com"))
        rec = dissect(bytes(pkt), 1700000000.0, 1)
        self.assertEqual(rec.proto, "TLS")
        self.assertIn("www.github.com", rec.info)
        self.assertEqual(rec.app["tls"]["sni"], "www.github.com")

    def test_ipv6(self):
        pkt = eth() / IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=5000, dport=6000) / Raw(b"hi")
        rec = dissect(bytes(pkt), 1700000000.0, 1)
        self.assertEqual(rec.src, "2001:db8::1")
        self.assertIn("ipv6", rec.layers)

    def test_tree(self):
        pkt = eth() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="S")
        rec = dissect(bytes(pkt), 1700000000.0, 7)
        tree = build_tree(rec)
        self.assertIn("Frame 7", tree.label)
        labels = [node.label for node in tree.children]
        self.assertTrue(any("Ethernet" in label for label in labels))
        self.assertTrue(any("Internet Protocol" in label for label in labels))
        self.assertTrue(any("Transmission Control" in label for label in labels))

    def test_flag_text(self):
        self.assertIn("SYN", tcp_flags_text(0x002))
        self.assertIn("ACK", tcp_flags_text(0x010))


class FilterTest(unittest.TestCase):
    def setUp(self):
        self.http = dissect(bytes(
            eth() / IP(src="192.168.1.10", dst="93.184.216.34") / TCP(
                sport=40000, dport=80, flags="PA", seq=1) / Raw(
                b"GET /admin/login.php HTTP/1.1\r\nHost: test.example.com\r\n\r\n")
        ), 1700000000.0, 1)
        self.dns = dissect(bytes(
            eth() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=51000, dport=53)
            / DNS(id=1, rd=1, qd=DNSQR(qname="www.baidu.com"))
        ), 1700000000.1, 2)

    def test_protocol_keyword(self):
        self.assertTrue(DisplayFilter("http").match(self.http))
        self.assertFalse(DisplayFilter("http").match(self.dns))

    def test_logic(self):
        f = DisplayFilter("(tcp or udp) and not port 22")
        self.assertTrue(f.match(self.http))
        self.assertTrue(f.match(self.dns))
        f2 = DisplayFilter("http and http.host contains 'example'")
        self.assertTrue(f2.match(self.http))
        self.assertFalse(f2.match(self.dns))

    def test_comparison(self):
        self.assertTrue(DisplayFilter("tcp.port == 80").match(self.http))
        self.assertTrue(DisplayFilter("frame.len > 40").match(self.http))
        self.assertTrue(DisplayFilter("ip.addr == 8.8.8.8").match(self.dns))
        self.assertTrue(DisplayFilter("src port 51000").match(self.dns))

    def test_regex(self):
        self.assertTrue(DisplayFilter(r'http.request.uri matches "\.php$"').match(self.http))

    def test_invalid(self):
        self.assertIsNotNone(validate("http and (tcp"))
        with self.assertRaises(FilterSyntaxError):
            DisplayFilter("http && && tcp")


class FlowTest(unittest.TestCase):
    def test_reassembly_and_http(self):
        registry = FlowRegistry()
        segments = [
            (100, 0x002, b""),
            (101, 0x010, b""),
            (101, 0x018, b"GET / HTTP/1.1\r\nHost: demo.test\r\n\r\n"),
            (101, 0x010, b""),
        ]
        for i, (seq, flags, payload) in enumerate(segments):
            pkt = eth() / IP(src="10.0.0.5", dst="10.0.0.9") / TCP(
                sport=5555, dport=80, flags=flags, seq=seq) / (Raw(payload) if payload else Raw(b""))
            rec = dissect(bytes(pkt), 1700000000.0 + i * 0.01, i + 1)
            registry.feed_record(rec)

        streams = registry.tracker.streams()
        self.assertEqual(len(streams), 1)
        stream = streams[0]
        self.assertEqual(stream.client, ("10.0.0.5", 5555))
        self.assertIn("GET / HTTP/1.1", stream.client_text())
        transactions = stream.http_transactions()
        self.assertEqual(len(transactions), 1)
        self.assertEqual(transactions[0]["request"]["uri"], "/")


class StatsTest(unittest.TestCase):
    def test_hierarchy(self):
        collector = StatsCollector()
        pkt = eth() / IP() / TCP(sport=1, dport=80, flags="S")
        rec = dissect(bytes(pkt), 1700000000.0, 1)
        collector.feed(rec)
        tree = collector.hierarchy()
        self.assertEqual(collector.total, 1)

        def labels(node):
            for child in node.children:
                yield child.label
                yield from labels(child)

        self.assertTrue(any("TCP" in label for label in labels(tree)))


class PcapIoTest(unittest.TestCase):
    def test_roundtrip(self):
        packets = [
            eth() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1, dport=2, flags="S"),
            eth() / IP(src="2.2.2.2", dst="1.1.1.1") / UDP(sport=3, dport=4) / Raw(b"x"),
        ]
        records = [dissect(bytes(p), 1700000000.0 + i, i + 1) for i, p in enumerate(packets)]
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "t.pcap")
            self.assertEqual(save_pcap(path, records), 2)
            loaded, linktype = load_pcap(path)
            self.assertEqual(len(loaded), 2)
            self.assertEqual(linktype, 1)
            self.assertEqual(loaded[1].proto, "UDP")


if __name__ == "__main__":
    unittest.main(verbosity=2)
