"""pcap 文件读写（离线分析与取证回放）。

写：直接按 pcap 格式落盘，保留原始帧与纳秒级时间戳；
读：用 Scapy 的 PcapReader 兼容 pcap / pcapng。
"""

from __future__ import annotations

import struct
from typing import Callable, Iterable, Optional

from .dissector import dissect
from .models import PacketRecord

PCAP_MAGIC = 0xA1B2C3D4
PCAP_SNAPLEN = 262144


def save_pcap(path: str, records: Iterable[PacketRecord], linktype: Optional[int] = None) -> int:
    records = list(records)
    if not records:
        return 0
    dlt = linktype if linktype is not None else records[0].linktype
    count = 0
    with open(path, "wb") as handle:
        handle.write(struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, PCAP_SNAPLEN, dlt))
        for rec in records:
            ts_sec = int(rec.ts)
            ts_usec = int(round((rec.ts - ts_sec) * 1_000_000))
            if ts_usec >= 1_000_000:
                ts_sec += 1
                ts_usec -= 1_000_000
            data = rec.raw
            handle.write(struct.pack("<IIII", ts_sec, ts_usec, len(data), rec.length))
            handle.write(data)
            count += 1
    return count


def load_pcap(path: str, progress: Optional[Callable[[int], None]] = None,
              max_packets: int = 0) -> tuple[list[PacketRecord], int]:
    """读取 pcap/pcapng，返回 (记录列表, 链路层类型)。"""
    from scapy.utils import PcapReader

    records: list[PacketRecord] = []
    linktype = 1
    with PcapReader(path) as reader:
        linktype = int(getattr(reader, "linktype", 1) or 1)
        for index, pkt in enumerate(reader, start=1):
            try:
                ts = float(pkt.time)
            except Exception:
                ts = 0.0
            rec = dissect(bytes(pkt), ts, index, linktype)
            records.append(rec)
            if progress is not None and index % 500 == 0:
                progress(index)
            if max_packets and index >= max_packets:
                break
    if progress is not None:
        progress(len(records))
    return records, linktype
