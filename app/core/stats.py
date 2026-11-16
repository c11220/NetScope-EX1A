"""统计：协议分层占比、会话（端点对）、每秒包数（IO 图数据）。"""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable, Optional

from .models import PacketRecord, TreeNode

_LAYER_TITLES = {
    "ether": "Ethernet (链路层)",
    "dot1q": "802.1Q VLAN",
    "arp": "ARP",
    "ip": "IPv4 (网络层)",
    "ipv6": "IPv6 (网络层)",
    "tcp": "TCP (传输层)",
    "udp": "UDP (传输层)",
    "icmp": "ICMP",
    "icmpv6": "ICMPv6",
    "dns": "DNS (应用层)",
    "http": "HTTP (应用层)",
    "tls": "TLS (应用层)",
    "dhcp": "DHCP (应用层)",
}

_LAYER_ORDER = ["ether", "dot1q", "arp", "ip", "ipv6", "tcp", "udp", "icmp",
                "icmpv6", "dns", "http", "tls", "dhcp"]


def _title(name: str) -> str:
    return _LAYER_TITLES.get(name, name.upper())


class _CountNode:
    __slots__ = ("count", "children")

    def __init__(self) -> None:
        self.count = 0
        self.children: dict[str, "_CountNode"] = {}


class StatsCollector:
    def __init__(self) -> None:
        self.total = 0
        self.total_bytes = 0
        self._root = _CountNode()
        self._conversations: dict[tuple, dict] = {}
        self._io: dict[int, int] = {}
        self._start_ts: Optional[float] = None

    def reset(self) -> None:
        self.__init__()

    def feed(self, rec: PacketRecord) -> None:
        self.total += 1
        self.total_bytes += rec.length
        if self._start_ts is None:
            self._start_ts = rec.ts

        chain = [layer for layer in _LAYER_ORDER if layer in rec.layers]
        if not chain:
            chain = [rec.proto.lower()]
        # HTTP/TLS 不是 Scapy 的独立层，但它们是真正的应用层协议，
        # 统计时应挂在传输层之下（与 Wireshark 的 Protocol Hierarchy 一致）
        app_proto = rec.proto.lower()
        if app_proto in ("http", "tls", "dns", "dhcp") and app_proto not in chain:
            chain.append(app_proto)
        node = self._root
        for name in chain:
            node = node.children.setdefault(name, _CountNode())
            node.count += 1

        proto = rec.proto if rec.proto not in ("TCP", "UDP") else rec.proto
        a = (rec.src, rec.sport)
        b = (rec.dst, rec.dport)
        pair = (a, b) if a <= b else (b, a)
        key = (proto, pair)
        conv = self._conversations.get(key)
        if conv is None:
            conv = self._conversations[key] = {
                "protocol": proto, "a": pair[0], "b": pair[1],
                "packets": 0, "bytes": 0,
                "start": rec.ts, "end": rec.ts,
                "a_bytes": 0, "b_bytes": 0,
            }
        conv["packets"] += 1
        conv["bytes"] += rec.length
        conv["end"] = max(conv["end"], rec.ts)
        if a == pair[0]:
            conv["a_bytes"] += rec.length
        else:
            conv["b_bytes"] += rec.length

        second = int(rec.ts)
        self._io[second] = self._io.get(second, 0) + 1

    # ------------------------------------------------------------ 快照

    def hierarchy(self) -> TreeNode:
        """协议分层树（类似 Wireshark 的 Protocol Hierarchy）。"""

        def walk(node: _CountNode, label: str) -> TreeNode:
            percent = (node.count / self.total * 100) if self.total else 0.0
            tree = TreeNode(label, f"{node.count} 包, {percent:.1f}%")
            for name, child in sorted(node.children.items(), key=lambda kv: -kv[1].count):
                tree.children.append(walk(child, _title(name)))
            return tree

        root = TreeNode(f"Frame 总数", f"{self.total} 包, {self.total_bytes} 字节")
        for name, child in sorted(self._root.children.items(), key=lambda kv: -kv[1].count):
            root.children.append(walk(child, _title(name)))
        return root

    def protocol_counts(self) -> list[tuple[str, int]]:
        counts: dict[str, int] = defaultdict(int)
        for (proto, _pair), conv in self._conversations.items():
            counts[proto] += conv["packets"]
        return sorted(counts.items(), key=lambda kv: -kv[1])

    def conversations(self) -> list[dict]:
        return sorted(self._conversations.values(), key=lambda c: -c["bytes"])

    def io_series(self) -> tuple[list[int], list[int]]:
        if not self._io:
            return [], []
        lo, hi = min(self._io), max(self._io)
        seconds = list(range(lo, hi + 1))
        return seconds, [self._io.get(s, 0) for s in seconds]


def endpoint_text(endpoint: tuple) -> str:
    ip, port = endpoint
    return f"{ip}:{port}" if port is not None else ip


def top_talkers(records: Iterable[PacketRecord], limit: int = 10) -> list[tuple[str, int]]:
    counter: dict[str, int] = defaultdict(int)
    for rec in records:
        counter[rec.src] += rec.length
    return sorted(counter.items(), key=lambda kv: -kv[1])[:limit]
