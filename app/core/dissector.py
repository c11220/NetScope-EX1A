"""协议解析（NPA）：把链路层原始帧解析为列表摘要 + OSI 分层树。

设计要点
--------
1. 抓包线程只做 ``dissect()``（轻量摘要），完整协议树在用户点选某一行时
   才通过 ``build_tree()`` 按需重建，避免大流量下 GUI 卡死。
2. 解析严格遵循 OSI 分层：物理/链路（Ethernet/VLAN）→ 网络（IPv4/IPv6/ARP）
   → 传输（TCP/UDP/ICMP）→ 应用（HTTP/DNS/TLS/DHCP）。
"""

from __future__ import annotations

import time
from typing import Any, Optional

from scapy.config import conf
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6, ICMPv6EchoReply, ICMPv6EchoRequest
from scapy.layers.l2 import ARP, Dot1Q, Ether
from scapy.packet import Packet, Raw

from .models import PacketRecord, TreeNode
from .protocols import (
    decode_domain,
    is_http_request,
    is_http_response,
    is_tls_record,
    parse_http,
    parse_tls_client_hello,
    summarize_http,
    tls_version_name,
)

# 常见端口 → 应用层协议（用于“协议”列的启发式标注）
PORT_HINTS: dict[int, str] = {
    20: "FTP", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 123: "NTP", 143: "IMAP", 161: "SNMP", 389: "LDAP",
    443: "TLS", 445: "SMB", 587: "SMTP", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5353: "MDNS", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP",
    8443: "HTTPS", 9090: "HTTP",
}

TCP_FLAG_NAMES = [
    (0x100, "NS"), (0x080, "CWR"), (0x040, "ECE"), (0x020, "URG"),
    (0x010, "ACK"), (0x008, "PSH"), (0x004, "RST"), (0x002, "SYN"),
    (0x001, "FIN"),
]

ICMP_TYPE_NAMES = {
    0: "Echo (ping) reply", 3: "Destination unreachable",
    5: "Redirect", 8: "Echo (ping) request", 11: "Time-to-live exceeded",
    13: "Timestamp request", 14: "Timestamp reply",
}


def tcp_flags_text(flags: int) -> str:
    names = [name for bit, name in TCP_FLAG_NAMES if flags & bit]
    return f"0x{flags:03x} ({', '.join(names)})" if names else f"0x{flags:03x}"


def tcp_flags_short(flags: int) -> str:
    return ", ".join(name for bit, name in TCP_FLAG_NAMES if flags & bit)


def _fmt_value(value: Any) -> str:
    if isinstance(value, (bytes, bytearray)):
        data = bytes(value)
        if len(data) <= 24:
            return data.hex(" ")
        return data[:24].hex(" ") + f" … ({len(data)} bytes)"
    if isinstance(value, (list, tuple)):
        if not value:
            return ""
        return ", ".join(_fmt_value(v) for v in value)
    if isinstance(value, dict):
        return str(value)
    return str(value)


def _port_service(sport: Optional[int], dport: Optional[int]) -> Optional[str]:
    for port in (dport, sport):
        if port in PORT_HINTS:
            return PORT_HINTS[port]
    return None


# --------------------------------------------------------------------------
# 列表摘要
# --------------------------------------------------------------------------

_CLASS_TO_KEY = {
    "Ether": "ether", "Dot1Q": "dot1q", "ARP": "arp", "IP": "ip", "IPv6": "ipv6",
    "TCP": "tcp", "UDP": "udp", "ICMP": "icmp", "DNS": "dns", "DHCP": "dhcp",
    "BOOTP": "dhcp", "Raw": "raw", "Padding": "padding",
}


def layer_key(layer: Packet) -> str:
    cls_name = layer.__class__.__name__
    if cls_name.startswith("ICMPv6"):
        return "icmpv6"
    return _CLASS_TO_KEY.get(cls_name, cls_name.lower())


def iter_layers(pkt: Packet):
    """按从下到上的顺序迭代 Scapy 的报文层实例。"""
    layer = pkt
    seen = 0
    while layer is not None and seen < 32:
        yield layer
        payload = layer.payload
        if payload is None or payload.__class__.__name__ == "NoPayload":
            break
        layer = payload
        seen += 1


def dissect(raw: bytes, ts: float, index: int, linktype: int = 1) -> PacketRecord:
    """把一个链路层帧解析为列表行所需的摘要信息。"""
    record = PacketRecord(
        index=index, ts=ts, raw=raw, caplen=len(raw), length=len(raw),
        linktype=linktype,
    )
    try:
        layer_cls = conf.l2types.num2layer.get(linktype, Ether)
        pkt = layer_cls(raw)
    except Exception:
        record.proto = "MALFORMED"
        record.info = "无法解析的帧（长度不足或链路层类型不支持）"
        return record

    layers: list[str] = []
    for layer in iter_layers(pkt):
        name = layer_key(layer)
        if name not in layers:
            layers.append(name)
    record.layers = tuple(layers)

    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        record.src_mac = eth.src
        record.dst_mac = eth.dst

    ip_layer = None
    if pkt.haslayer(IP):
        ip_layer = pkt[IP]
        record.src, record.dst = ip_layer.src, ip_layer.dst
    elif pkt.haslayer(IPv6):
        ip_layer = pkt[IPv6]
        record.src, record.dst = ip_layer.src, ip_layer.dst

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        record.sport, record.dport = tcp.sport, tcp.dport
        record.flow_key = (record.src, tcp.sport, record.dst, tcp.dport)
        record.tcp_seq = int(tcp.seq)
        record.tcp_flags = int(tcp.flags)
        record.payload = bytes(tcp.payload) if tcp.payload else b""
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        record.sport, record.dport = udp.sport, udp.dport
        record.flow_key = (record.src, udp.sport, record.dst, udp.dport)
        record.payload = bytes(udp.payload) if udp.payload else b""

    record.proto, record.info, record.app = _classify(pkt, record)
    return record


def _classify(pkt: Packet, rec: PacketRecord) -> tuple[str, str, Optional[dict[str, Any]]]:
    """决定“协议”列与“信息”列的内容，并抽取应用层元数据。"""
    app: Optional[dict[str, Any]] = None
    service = _port_service(rec.sport, rec.dport)

    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        if int(arp.op) == 1:
            info = f"Who has {arp.pdst}? Tell {arp.psrc}"
        else:
            info = f"{arp.psrc} is at {arp.hwsrc}"
        return "ARP", info, None

    if pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        tname = ICMP_TYPE_NAMES.get(int(icmp.type), f"Type {int(icmp.type)}")
        if int(icmp.type) in (0, 8):
            seq = int(getattr(icmp, "seq", 0))
            ident = int(getattr(icmp, "id", 0))
            info = f"Echo (ping) {'reply' if int(icmp.type) == 0 else 'request'} id=0x{ident:04x} seq={seq}"
        else:
            info = tname
        return "ICMP", info, None

    if pkt.haslayer(ICMPv6EchoRequest) or pkt.haslayer(ICMPv6EchoReply):
        layer = pkt[ICMPv6EchoRequest] if pkt.haslayer(ICMPv6EchoRequest) else pkt[ICMPv6EchoReply]
        kind = "request" if pkt.haslayer(ICMPv6EchoRequest) else "reply"
        return "ICMPv6", f"Echo (ping) {kind} id=0x{int(getattr(layer, 'id', 0)):04x}", None

    if pkt.haslayer(DHCP):
        dhcp = pkt[DHCP]
        msg = "DHCP"
        for opt in dhcp.options:
            if opt[0] == "message-type":
                names = {1: "Discover", 2: "Offer", 3: "Request", 4: "Decline",
                         5: "ACK", 6: "NAK", 7: "Release", 8: "Inform"}
                msg = f"DHCP {names.get(opt[1], opt[1])}"
        return "DHCP", msg, None

    if pkt.haslayer(DNS):
        dns = pkt[DNS]
        qname = ""
        qtype = ""
        try:
            if dns.qd is not None and int(dns.qdcount) > 0:
                qname = decode_domain(dns.qd.qname)
                qtype = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT",
                         12: "PTR", 6: "SOA", 65: "HTTPS"}.get(int(dns.qd.qtype), str(int(dns.qd.qtype)))
        except Exception:
            pass
        if int(dns.qr) == 0:
            info = f"Standard query {int(dns.id):#06x} {qtype} {qname}".replace("  ", " ").strip()
        else:
            info = f"Standard query response {int(dns.id):#06x} {qtype} {qname}".strip()
        app = {"dns": {"qname": qname, "qtype": qtype, "answers": int(dns.ancount)}}
        return "DNS", info, app

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        payload = bytes(tcp.payload) if tcp.payload else b""
        flags = int(tcp.flags)

        if payload and is_http_request(payload):
            http = parse_http(payload)
            if http:
                app = {"http": http}
                return "HTTP", summarize_http(http), app
        if payload and is_http_response(payload):
            http = parse_http(payload)
            if http:
                app = {"http": http}
                return "HTTP", summarize_http(http), app
        if payload and (service in ("TLS", "HTTPS", None)) and is_tls_record(payload) and payload[0] == 0x16:
            hello = parse_tls_client_hello(payload)
            if hello:
                app = {"tls": hello}
                sni = hello.get("sni")
                ver = tls_version_name(hello.get("version", 0))
                if sni:
                    return "TLS", f"Client Hello ({ver}) server_name={sni}", app
                return "TLS", f"Client Hello ({ver})", app

        seq, ack, win = int(tcp.seq), int(tcp.ack), int(tcp.window)
        plen = len(payload)
        prefix = tcp_flags_short(flags) or "?"
        if flags & 0x002:
            info = f"[SYN] Seq={seq} Win={win} Len={plen}"
        elif flags & 0x010 and not plen and not flags & (0x001 | 0x004):
            info = f"[ACK] Seq={seq} Ack={ack} Win={win} Len=0"
        elif flags & 0x001:
            info = f"[FIN, ACK] Seq={seq} Ack={ack} Len={plen}"
        elif flags & 0x004:
            info = f"[RST, ACK] Seq={seq} Ack={ack} Len={plen}"
        else:
            info = f"[{prefix}] Seq={seq} Ack={ack} Win={win} Len={plen}"
        if payload:
            text = payload[:64].decode("latin-1", "replace").replace("\r", " ").replace("\n", " ")
            info += f"  {text}"
        return (service or "TCP"), info, None

    if pkt.haslayer(UDP):
        udp = pkt[UDP]
        length = int(udp.len) - 8 if udp.len else 0
        return (service or "UDP"), f"Source port: {udp.sport}  Destination port: {udp.dport}  Length: {max(length, 0)}", None

    if pkt.haslayer(IPv6):
        return "IPv6", "IPv6 报文", None
    if pkt.haslayer(IP):
        ip = pkt[IP]
        return "IPv4", f"{ip.src} → {ip.dst}  proto={int(ip.proto)}", None

    return "ETHERNET", "Ethernet 帧", None


# --------------------------------------------------------------------------
# 协议详情树
# --------------------------------------------------------------------------

_LAYER_TITLES = {
    "Ether": "Ethernet II, Src: {src}, Dst: {dst}",
    "Dot1Q": "802.1Q Virtual LAN, PRI: {prio}, ID: {id}",
    "ARP": "Address Resolution Protocol ({op})",
    "IP": "Internet Protocol Version 4, Src: {src}, Dst: {dst}",
    "IPv6": "Internet Protocol Version 6, Src: {src}, Dst: {dst}",
    "TCP": "Transmission Control Protocol, Src Port: {sport}, Dst Port: {dport}, Seq: {seq}, Ack: {ack}, Len: {plen}",
    "UDP": "User Datagram Protocol, Src Port: {sport}, Dst Port: {dport}",
    "ICMP": "Internet Control Message Protocol",
    "DNS": "Domain Name System",
    "DHCP": "Dynamic Host Configuration Protocol",
}

_FIELD_LABELS = {
    "Ether": {"dst": "Destination", "src": "Source", "type": "Type"},
    "IP": {"version": "Version", "ihl": "Header Length", "tos": "Differentiated Services Field",
           "len": "Total Length", "id": "Identification", "flags": "Flags",
           "frag": "Fragment Offset", "ttl": "Time to Live", "proto": "Protocol",
           "chksum": "Header Checksum", "src": "Source Address", "dst": "Destination Address",
           "options": "Options"},
    "IPv6": {"version": "Version", "tc": "Traffic Class", "fl": "Flow Label",
             "plen": "Payload Length", "nh": "Next Header", "hlim": "Hop Limit",
             "src": "Source Address", "dst": "Destination Address"},
    "TCP": {"sport": "Source Port", "dport": "Destination Port", "seq": "Sequence Number",
            "ack": "Acknowledgment Number", "dataofs": "Header Length", "reserved": "Reserved",
            "flags": "Flags", "window": "Window", "chksum": "Checksum",
            "urgptr": "Urgent Pointer", "options": "Options"},
    "UDP": {"sport": "Source Port", "dport": "Destination Port", "len": "Length", "chksum": "Checksum"},
    "ICMP": {"type": "Type", "code": "Code", "chksum": "Checksum", "id": "Identifier",
             "seq": "Sequence Number"},
    "ARP": {"hwtype": "Hardware Type", "ptype": "Protocol Type", "hwlen": "Hardware Size",
            "plen": "Protocol Size", "op": "Opcode", "hwsrc": "Sender MAC address",
            "psrc": "Sender IP address", "hwdst": "Target MAC address", "pdst": "Target IP address"},
    "DNS": {"id": "Transaction ID", "qr": "Response", "opcode": "Opcode", "aa": "Authoritative",
            "tc": "Truncated", "rd": "Recursion desired", "ra": "Recursion available",
            "qdcount": "Questions", "ancount": "Answer RRs", "nscount": "Authority RRs",
            "arcount": "Additional RRs"},
}

_PROTO_NUM = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}


def _layer_node(layer: Packet) -> TreeNode:
    cls_name = layer.__class__.__name__
    fields = layer.fields

    if cls_name == "TCP":
        title = _LAYER_TITLES["TCP"].format(
            sport=fields.get("sport"), dport=fields.get("dport"),
            seq=fields.get("seq", 0), ack=fields.get("ack", 0),
            plen=len(layer.payload) if layer.payload else 0,
        )
    elif cls_name == "ARP":
        title = _LAYER_TITLES["ARP"].format(op="request" if int(fields.get("op", 0)) == 1 else "reply")
    else:
        template = _LAYER_TITLES.get(cls_name)
        if template:
            try:
                title = template.format(**fields)
            except (KeyError, IndexError):
                title = layer.name
        else:
            title = layer.name

    node = TreeNode(title)
    labels = _FIELD_LABELS.get(cls_name, {})

    for key, value in fields.items():
        label = labels.get(key, key)
        if cls_name == "TCP" and key == "flags":
            value_text = tcp_flags_text(int(value))
        elif cls_name == "Ether" and key == "type":
            eth_types = {0x0800: "IPv4", 0x86DD: "IPv6", 0x0806: "ARP", 0x8100: "802.1Q"}
            value_text = f"0x{int(value):04x} ({eth_types.get(int(value), 'Unknown')})"
        elif cls_name == "IP" and key == "proto":
            pnum = int(value)
            value_text = f"{_PROTO_NUM.get(pnum, 'Unknown')} ({pnum})"
        elif cls_name == "IP" and key == "len":
            value_text = f"{int(value)}"
        elif cls_name == "TCP" and key == "dataofs":
            value_text = f"{int(value) * 4} bytes ({int(value)})"
        else:
            value_text = _fmt_value(value)
        child = TreeNode(label, value_text)
        if key == "options" and isinstance(value, list):
            for opt in value:
                child.add(str(getattr(opt, "name", opt)), _fmt_value(getattr(opt, "fields", opt)))
        node.children.append(child)

    return node


def _http_node(http: dict[str, Any]) -> TreeNode:
    if http.get("type") == "request":
        node = TreeNode(
            f"Hypertext Transfer Protocol: {http.get('method')} {http.get('uri')} HTTP/{http.get('version')}"
        )
        node.add("Request Method", http.get("method", ""))
        node.add("Request URI", http.get("uri", ""))
        node.add("Request Version", f"HTTP/{http.get('version')}")
    else:
        node = TreeNode(
            f"Hypertext Transfer Protocol: HTTP/{http.get('version')} {http.get('status')} {http.get('reason', '')}".strip()
        )
        node.add("Response Version", f"HTTP/{http.get('version')}")
        node.add("Status Code", str(http.get("status")))
        node.add("Response Phrase", http.get("reason", ""))

    headers_node = node.add("Headers")
    for name, value in http.get("headers", []):
        headers_node.add(name, value)
    if http.get("body_len"):
        node.add("Body", f"{http['body_len']} bytes")
    return node


def _tls_node(tls: dict[str, Any]) -> TreeNode:
    node = TreeNode(f"Transport Layer Security: {tls_version_name(tls.get('version', 0))} Client Hello")
    if tls.get("sni"):
        node.add("server_name (SNI)", tls["sni"])
    return node


def build_tree(record: PacketRecord) -> TreeNode:
    """按需重建完整协议树（OSI 逐层展开）。"""
    root = TreeNode(
        f"Frame {record.index}: {record.length} bytes on wire, {record.caplen} bytes captured",
    )
    root.add("Interface", f"DLT {record.linktype}")
    root.add("Arrival Time", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(record.ts))
             + f".{int(record.ts * 1_000_000) % 1_000_000:06d}")
    root.add("Frame Number", str(record.index))
    if record.pname:
        root.add("Process", f"{record.pname} (pid={record.pid})")

    try:
        layer_cls = conf.l2types.num2layer.get(record.linktype, Ether)
        pkt = layer_cls(record.raw)
    except Exception:
        root.add("Error", "无法解析该帧")
        return root

    for layer in iter_layers(pkt):
        if layer.__class__.__name__ in ("Raw", "Padding", "NoPayload"):
            continue
        root.children.append(_layer_node(layer))

    if record.app:
        if "http" in record.app:
            root.children.append(_http_node(record.app["http"]))
        if "tls" in record.app:
            root.children.append(_tls_node(record.app["tls"]))
        if "dns" in record.app:
            dns_node = TreeNode("Domain Name System (应用层解析)")
            dns_node.add("Query Name", record.app["dns"].get("qname", ""))
            dns_node.add("Query Type", record.app["dns"].get("qtype", ""))
            dns_node.add("Answer Count", str(record.app["dns"].get("answers", 0)))
            root.children.append(dns_node)

    # 未识别为具名协议时，补充一段 ASCII 预览，便于人工判读
    if record.layers and record.layers[-1] in ("tcp", "udp", "ip", "ipv6"):
        payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
        if payload:
            preview = payload[:256]
            text_lines = preview.decode("latin-1", "replace").splitlines()[:6]
            node = TreeNode(f"Data ({len(payload)} bytes)")
            for line in text_lines:
                node.add("ASCII", line[:120])
            root.children.append(node)

    return root


def record_from_scapy(pkt: Packet, index: int, ts: Optional[float] = None) -> PacketRecord:
    """从 Scapy 报文对象生成记录（用于读取 pcap 文件）。"""
    if ts is None:
        try:
            ts = float(pkt.time)
        except Exception:
            ts = time.time()
    data = bytes(pkt)
    return dissect(data, ts, index)
