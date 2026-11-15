"""TCP 流追踪：按 IP+Port 四元组重组字节流，并提取 HTTP 会话。

这是实验的加分项之一：
* 基于 IP + Port 的 TCP 流重组；
* 从重组结果中还原 HTTP 请求/响应（“识别特定类型的应用层报文”）。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from .models import PacketRecord
from .protocols import decode_text, parse_http

MAX_DIRECTION_BYTES = 512 * 1024   # 单方向最多保留 512 KiB，防止内存膨胀


def _endpoint_key(ip: str, port: int) -> tuple[str, int]:
    return (ip, port)


@dataclass
class TcpStream:
    client: tuple[str, int]
    server: tuple[str, int]
    first_ts: float
    last_ts: float
    packets: int = 0
    bytes_c2s: int = 0
    bytes_s2c: int = 0
    syn_seen: bool = False
    fin_seen: bool = False
    rst_seen: bool = False
    pname: str = ""
    pid: Optional[int] = None
    _c2s: dict[int, bytes] = field(default_factory=dict)
    _s2c: dict[int, bytes] = field(default_factory=dict)

    @property
    def key_text(self) -> str:
        return f"{self.client[0]}:{self.client[1]} ↔ {self.server[0]}:{self.server[1]}"

    @property
    def duration(self) -> float:
        return max(0.0, self.last_ts - self.first_ts)

    @property
    def state(self) -> str:
        if self.rst_seen:
            return "RST"
        if self.fin_seen:
            return "CLOSED"
        if self.syn_seen:
            return "ESTABLISHED"
        return "ONGOING"

    # ------------------------------------------------------- 数据写入

    def add(self, rec: PacketRecord, seq: int, payload: bytes, flags: int) -> None:
        self.packets += 1
        self.last_ts = rec.ts
        if rec.pname and not self.pname:
            self.pname, self.pid = rec.pname, rec.pid
        if flags & 0x002:
            self.syn_seen = True
        if flags & 0x001:
            self.fin_seen = True
        if flags & 0x004:
            self.rst_seen = True
        if not payload:
            return

        is_c2s = (rec.src, rec.sport) == self.client
        target = self._c2s if is_c2s else self._s2c
        if is_c2s:
            self.bytes_c2s += len(payload)
        else:
            self.bytes_s2c += len(payload)
        if sum(len(v) for v in target.values()) < MAX_DIRECTION_BYTES:
            target.setdefault(seq, payload)

    # ------------------------------------------------------- 重组

    @staticmethod
    def _join(segments: dict[int, bytes]) -> bytes:
        if not segments:
            return b""
        parts: list[bytes] = []
        expected: Optional[int] = None
        for seq in sorted(segments):
            data = segments[seq]
            if expected is None:
                parts.append(data)
            elif seq > expected:
                parts.append(data)          # 有空洞，直接拼接（保留可读性）
            elif seq < expected:
                overlap = expected - seq
                if overlap < len(data):
                    parts.append(data[overlap:])
                else:
                    continue
            else:
                continue
            expected = seq + len(data)
        return b"".join(parts)

    def client_bytes(self) -> bytes:
        return self._join(self._c2s)

    def server_bytes(self) -> bytes:
        return self._join(self._s2c)

    def client_text(self) -> str:
        return decode_text(self.client_bytes())

    def server_text(self) -> str:
        return decode_text(self.server_bytes())

    # ------------------------------------------------------- HTTP 还原

    def http_transactions(self) -> list[dict]:
        """尽力从双向字节流中还原本流上的 HTTP 事务。"""
        cdata = self.client_bytes()
        sdata = self.server_bytes()
        requests, responses = [], []

        pos = 0
        while pos < len(cdata):
            http = parse_http(cdata[pos:])
            if not http or http.get("type") != "request":
                break
            requests.append(http)
            head_end = cdata.find(b"\r\n\r\n", pos)
            if head_end < 0:
                break
            pos = head_end + 4 + min(http.get("body_len", 0), 1 << 20)

        pos = 0
        while pos < len(sdata):
            http = parse_http(sdata[pos:])
            if not http or http.get("type") != "response":
                break
            responses.append(http)
            head_end = sdata.find(b"\r\n\r\n", pos)
            if head_end < 0:
                break
            pos = head_end + 4 + min(http.get("body_len", 0), 1 << 20)

        transactions = []
        for i in range(max(len(requests), len(responses))):
            req = requests[i] if i < len(requests) else None
            resp = responses[i] if i < len(responses) else None
            transactions.append({"request": req, "response": resp})
        return transactions


class FlowTracker:
    """管理所有 TCP 流。"""

    def __init__(self, max_streams: int = 20_000):
        self._streams: dict[tuple, TcpStream] = {}
        self._max = max_streams

    @staticmethod
    def _canonical(src: str, sport: int, dst: str, dport: int) -> tuple:
        a, b = _endpoint_key(src, sport), _endpoint_key(dst, dport)
        return (a, b) if a <= b else (b, a)

    def feed(self, rec: PacketRecord, seq: int, payload: bytes, flags: int) -> Optional[TcpStream]:
        if rec.sport is None or rec.dport is None:
            return None
        key = self._canonical(rec.src, rec.sport, rec.dst, rec.dport)
        stream = self._streams.get(key)
        if stream is None:
            if len(self._streams) >= self._max:
                return None
            has_syn = bool(flags & 0x002)
            client, server = ((rec.src, rec.sport), (rec.dst, rec.dport))
            if not has_syn:
                # 没有握手时用“端口较大者视为客户端”的经验规则
                if rec.dport and rec.sport and rec.sport > rec.dport:
                    client, server = (rec.dst, rec.dport), (rec.src, rec.sport)
            stream = TcpStream(client=client, server=server,
                               first_ts=rec.ts, last_ts=rec.ts)
            self._streams[key] = stream
        elif flags & 0x002 and not flags & 0x010 and not stream.syn_seen:
            stream.client = (rec.src, rec.sport)
            stream.server = (rec.dst, rec.dport)
        stream.add(rec, seq, payload, flags)
        return stream

    def streams(self) -> list[TcpStream]:
        return list(self._streams.values())

    def clear(self) -> None:
        self._streams.clear()

    def __len__(self) -> int:
        return len(self._streams)


class FlowRegistry:
    """按记录索引缓存流编号，供界面展示“流 N”。"""

    def __init__(self) -> None:
        self.tracker = FlowTracker()
        self._index_by_key: dict[tuple, int] = {}
        self.started_at = time.time()

    def reset(self) -> None:
        self.tracker.clear()
        self._index_by_key.clear()
        self.started_at = time.time()

    def feed_record(self, rec: PacketRecord) -> None:
        if rec.tcp_seq is None or "tcp" not in rec.layers:
            return
        stream = self.tracker.feed(rec, rec.tcp_seq, rec.payload, rec.tcp_flags)
        if stream is not None:
            key = self.tracker._canonical(rec.src, rec.sport, rec.dst, rec.dport)
            number = self._index_by_key.get(key)
            if number is None:
                number = self._index_by_key[key] = len(self._index_by_key)
            rec.flow_no = number
