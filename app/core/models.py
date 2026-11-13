"""数据模型：一条被捕获报文的轻量视图与协议树节点。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass(slots=True)
class PacketRecord:
    """一条报文的“列表视图”数据。

    只保存摘要与原始字节，完整协议树在选中行时按需重建，
    因此百万级抓包也不会撑爆内存。
    """

    index: int                 # 捕获序号，从 1 开始
    ts: float                  # 抓包时间戳（epoch 秒）
    raw: bytes                 # 原始链路层帧
    caplen: int                # 实际捕获长度
    length: int                # 报文原始长度（wire length）
    linktype: int = 1          # DLT，1=EN10MB
    layers: tuple[str, ...] = ()   # 参与解析的协议层（小写）
    proto: str = "UNKNOWN"     # 用于“协议”列显示的最高层协议
    src: str = ""
    dst: str = ""
    sport: Optional[int] = None
    dport: Optional[int] = None
    src_mac: str = ""
    dst_mac: str = ""
    info: str = ""
    flow_key: Optional[tuple] = None
    pid: Optional[int] = None
    pname: str = ""
    app: Optional[dict[str, Any]] = None   # 应用层元数据（HTTP/TLS/DNS 等）
    tcp_seq: Optional[int] = None          # TCP 序号，用于流重组
    tcp_flags: int = 0                     # TCP 标志位
    payload: bytes = b""                   # 传输层载荷，用于流重组
    flow_no: Optional[int] = None          # 所属 TCP 流编号

    @property
    def time_text(self) -> str:
        import time

        return time.strftime("%H:%M:%S", time.localtime(self.ts)) + f".{int(self.ts * 1000) % 1000:03d}"

    def src_endpoint(self) -> str:
        if self.sport is None:
            return self.src
        return f"{self.src}:{self.sport}"

    def dst_endpoint(self) -> str:
        if self.dport is None:
            return self.dst
        return f"{self.dst}:{self.dport}"


@dataclass(slots=True)
class TreeNode:
    """协议详情树的一个节点。"""

    label: str
    value: str = ""
    children: list["TreeNode"] = field(default_factory=list)

    def add(self, label: str, value: str = "") -> "TreeNode":
        node = TreeNode(label, value)
        self.children.append(node)
        return node
