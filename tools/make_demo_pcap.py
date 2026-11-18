"""生成用于离线演示与自动化截图的示例抓包（demo.pcap）。

这批报文完全在本地构造，不产生任何真实网络流量：
ARP → DNS → TCP 三次握手 → HTTP 请求/响应 → TLS ClientHello(SNI) →
ICMP 回显 → IPv6 DNS，共约 60 个报文。
"""

from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import PcapWriter

CLIENT_MAC = "3c:52:82:1a:7b:04"
GATEWAY_MAC = "a4:2b:8c:19:33:10"
SERVER_MAC = "00:1e:67:4d:9a:22"

CLIENT_IP = "192.168.1.23"
GATEWAY_IP = "192.168.1.1"
HTTP_SERVER = "93.184.216.34"
TLS_SERVER = "140.82.112.4"
DNS_SERVER = "8.8.8.8"


def tls_client_hello(sni: str) -> bytes:
    host = sni.encode()
    name_list = b"\x00" + struct.pack(">H", len(host)) + host
    ext_data = struct.pack(">H", len(name_list)) + name_list
    extensions = (
        b"\x00\x00" + struct.pack(">H", len(ext_data)) + ext_data
        + b"\x00\x0d" + struct.pack(">H", 4) + b"\x04\x01\x04\x00"   # signature_algorithms
    )
    body = (
        b"\x03\x03" + bytes(range(32))
        + b"\x20" + bytes(range(32))                                # session id
        + b"\x00\x04\x13\x01\x13\x02"                               # cipher suites
        + b"\x01\x00"                                               # compression
        + struct.pack(">H", len(extensions)) + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


class Builder:
    def __init__(self) -> None:
        self.packets: list = []
        self.ts = 1761400000.0
        self.ip_id = 1000

    def add(self, pkt, advance: float = 0.0009) -> None:
        self.ts += advance
        pkt.time = self.ts
        if pkt.haslayer(IP):
            pkt[IP].id = self.ip_id
            self.ip_id = (self.ip_id + 1) & 0xFFFF
        self.packets.append(pkt)

    # ---------------------------------------------------------------- 场景

    def arp(self) -> None:
        self.add(Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=1, hwsrc=CLIENT_MAC, hwdst="00:00:00:00:00:00",
            psrc=CLIENT_IP, pdst=GATEWAY_IP))
        self.add(Ether(src=GATEWAY_MAC, dst=CLIENT_MAC) / ARP(
            op=2, hwsrc=GATEWAY_MAC, hwdst=CLIENT_MAC,
            psrc=GATEWAY_IP, pdst=CLIENT_IP))

    def dns(self, name: str = "example.com", sport: int = 52110) -> None:
        self.add(Ether(src=CLIENT_MAC, dst=GATEWAY_MAC) / IP(src=CLIENT_IP, dst=DNS_SERVER)
                 / UDP(sport=sport, dport=53) / DNS(id=0xBEEF, rd=1, qd=DNSQR(qname=name)))
        self.add(Ether(src=GATEWAY_MAC, dst=CLIENT_MAC) / IP(src=DNS_SERVER, dst=CLIENT_IP)
                 / UDP(sport=53, dport=sport)
                 / DNS(id=0xBEEF, qr=1, aa=0, rd=1, ra=1, qd=DNSQR(qname=name),
                       an=DNSRR(rrname=name, type="A", ttl=300, rdata=HTTP_SERVER)))

    def http_session(self) -> None:
        sport = 52145
        seq_c, seq_s = 1000, 5000
        # 三次握手
        self.add(Ether(src=CLIENT_MAC, dst=GATEWAY_MAC) / IP(src=CLIENT_IP, dst=HTTP_SERVER)
                 / TCP(sport=sport, dport=80, flags="S", seq=seq_c, window=64240))
        self.add(Ether(src=GATEWAY_MAC, dst=CLIENT_MAC) / IP(src=HTTP_SERVER, dst=CLIENT_IP)
                 / TCP(sport=80, dport=sport, flags="SA", seq=seq_s, ack=seq_c + 1, window=65535))
        self.add(Ether(src=CLIENT_MAC, dst=GATEWAY_MAC) / IP(src=CLIENT_IP, dst=HTTP_SERVER)
                 / TCP(sport=sport, dport=80, flags="A", seq=seq_c + 1, ack=seq_s + 1, window=64240))

        # GET /
        request = (b"GET / HTTP/1.1\r\nHost: example.com\r\n"
                   b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) NetScope/1.0\r\n"
                   b"Accept: text/html,application/xhtml+xml\r\n"
                   b"Connection: keep-alive\r\n\r\n")
        self.add(Ether(src=CLIENT_MAC, dst=GATEWAY_MAC) / IP(src=CLIENT_IP, dst=HTTP_SERVER)
                 / TCP(sport=sport, dport=80, flags="PA", seq=seq_c + 1, ack=seq_s + 1,
                       window=64240) / Raw(request))
        seq_c += len(request)

        body = b"<!doctype html><html><head><title>Example Domain</title></head>" \
               b"<body><h1>Example Domain</h1><p>This domain is for use in examples.</p>" \
               b"</body></html>"
        response = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\n"
                    b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                    b"Server: ECS (dcb/7F83)\r\n"
                    b"Cache-Control: max-age=604800\r\n"
                    b"Connection: keep-alive\r\n\r\n" + body)
        self.add(Ether(src=GATEWAY_MAC, dst=CLIENT_MAC) / IP(src=HTTP_SERVER, dst=CLIENT_IP)
                 / TCP(sport=80, dport=sport, flags="PA", seq=seq_s + 1, ack=seq_c,
                       window=65535) / Raw(response))
        seq_s += len(response)
        self.add(Ether(src=CLIENT_MAC, dst=GATEWAY_MAC) / IP(src=CLIENT_IP, dst=HTTP_SERVER)
                 / TCP(sport=sport, dport=80, flags="A", seq=seq_c, ack=seq_s, window=64240))

        # POST /login.php（用于演示 http.request.method 过滤）
        form = b"username=admin&password=Passw0rd%21"
        request2 = (b"POST /login.php HTTP/1.1\r\nHost: example.com\r\n"
                    b"Content-Type: application/x-www-form-urlencoded\r\n"
                    b"Content-Length: " + str(len(form)).encode() + b"\r\n"
                    b"Cookie: session=8f3ac1\r\n\r\n" + form)
        self.add(Ether(src=CLIENT_MAC, dst=GATEWAY_MAC) / IP(src=CLIENT_IP, dst=HTTP_SERVER)
                 / TCP(sport=sport, dport=80, flags="PA", seq=seq_c, ack=seq_s,
                       window=64240) / Raw(request2))
        seq_c += len(request2)

        resp2 = (b"HTTP/1.1 302 Found\r\nLocation: /dashboard\r\n"
                 b"Content-Type: text/html\r\nContent-Length: 0\r\n\r\n")
        self.add(Ether(src=GATEWAY_MAC, dst=CLIENT_MAC) / IP(src=HTTP_SERVER, dst=CLIENT_IP)
                 / TCP(sport=80, dport=sport, flags="PA", seq=seq_s, ack=seq_c,
                       window=65535) / Raw(resp2))
        seq_s += len(resp2)

        # 挥手
        self.add(Ether(src=CLIENT_MAC, dst=GATEWAY_MAC) / IP(src=CLIENT_IP, dst=HTTP_SERVER)
                 / TCP(sport=sport, dport=80, flags="FA", seq=seq_c, ack=seq_s, window=64240))
        self.add(Ether(src=GATEWAY_MAC, dst=CLIENT_MAC) / IP(src=HTTP_SERVER, dst=CLIENT_IP)
                 / TCP(sport=80, dport=sport, flags="FA", seq=seq_s, ack=seq_c + 1, window=65535))
        self.add(Ether(src=CLIENT_MAC, dst=GATEWAY_MAC) / IP(src=CLIENT_IP, dst=HTTP_SERVER)
                 / TCP(sport=sport, dport=80, flags="A", seq=seq_c + 1, ack=seq_s + 1, window=64240))

    def tls_session(self) -> None:
        sport = 52188
        seq_c, seq_s = 7000, 9000
        self.add(Ether(src=CLIENT_MAC, dst=GATEWAY_MAC) / IP(src=CLIENT_IP, dst=TLS_SERVER)
                 / TCP(sport=sport, dport=443, flags="S", seq=seq_c, window=64240))
        self.add(Ether(src=GATEWAY_MAC, dst=CLIENT_MAC) / IP(src=TLS_SERVER, dst=CLIENT_IP)
                 / TCP(sport=443, dport=sport, flags="SA", seq=seq_s, ack=seq_c + 1, window=65535))
        self.add(Ether(src=CLIENT_MAC, dst=GATEWAY_MAC) / IP(src=CLIENT_IP, dst=TLS_SERVER)
                 / TCP(sport=sport, dport=443, flags="A", seq=seq_c + 1, ack=seq_s + 1,
                       window=64240))
        hello = tls_client_hello("github.com")
        self.add(Ether(src=CLIENT_MAC, dst=GATEWAY_MAC) / IP(src=CLIENT_IP, dst=TLS_SERVER)
                 / TCP(sport=sport, dport=443, flags="PA", seq=seq_c + 1, ack=seq_s + 1,
                       window=64240) / Raw(hello))
        self.add(Ether(src=GATEWAY_MAC, dst=CLIENT_MAC) / IP(src=TLS_SERVER, dst=CLIENT_IP)
                 / TCP(sport=443, dport=sport, flags="PA", seq=seq_s + 1, ack=seq_c + 1 + len(hello),
                       window=65535) / Raw(b"\x16\x03\x03\x00\x7a\x02" + bytes(120)))

    def icmp(self) -> None:
        payload = b"abcdefghijklmnopqrstuvwabcdefghi"
        self.add(Ether(src=CLIENT_MAC, dst=GATEWAY_MAC) / IP(src=CLIENT_IP, dst="223.5.5.5")
                 / ICMP(type=8, id=0x0abc, seq=1) / Raw(payload))
        self.add(Ether(src=GATEWAY_MAC, dst=CLIENT_MAC) / IP(src="223.5.5.5", dst=CLIENT_IP,
                                                            ttl=54)
                 / ICMP(type=0, id=0x0abc, seq=1) / Raw(payload))

    def ipv6_dns(self) -> None:
        self.add(Ether(src=CLIENT_MAC, dst=GATEWAY_MAC)
                 / IPv6(src="2408:8207:1234::23", dst="2400:3200::1") / UDP(sport=52200, dport=53)
                 / DNS(id=0x2026, rd=1, qd=DNSQR(qname="www.ucas.ac.cn", qtype="AAAA")))

    def noise(self, count: int = 24) -> None:
        """补充若干 TCP 保活与 UDP 杂包，让统计更有层次。"""
        sport = 53000
        for i in range(count):
            self.add(Ether(src=CLIENT_MAC, dst=GATEWAY_MAC)
                     / IP(src=CLIENT_IP, dst="203.0.113.77")
                     / TCP(sport=sport + i, dport=443, flags="A", seq=100 + i, ack=1,
                           window=64240))
            if i % 6 == 0:
                self.add(Ether(src=GATEWAY_MAC, dst=CLIENT_MAC)
                         / IP(src="203.0.113.77", dst=CLIENT_IP)
                         / TCP(sport=443, dport=sport + i, flags="PA", seq=1, ack=101 + i,
                               window=65535) / Raw(b"\x17\x03\x03\x00\x20" + b"\x00" * 32),
                         advance=0.004)

    def build(self) -> list:
        self.arp()
        self.dns("example.com")
        self.dns("github.com", sport=52111)
        self.http_session()
        self.tls_session()
        self.icmp()
        self.ipv6_dns()
        self.noise()
        return self.packets


def main() -> None:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out_dir = os.path.join(root, "demo")
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "demo.pcap")

    packets = Builder().build()
    writer = PcapWriter(path, linktype=1, sync=True)
    for pkt in packets:
        writer.write(pkt)
    writer.close()
    print(f"written {len(packets)} packets -> {path}")


if __name__ == "__main__":
    main()
