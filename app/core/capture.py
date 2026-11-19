"""抓包层（NPS）：网卡枚举、libpcap/Npcap 实时抓包、线程与队列。

线程模型
--------
抓包回调运行在 Scapy 的 ``AsyncSniffer`` 线程中，只做三件事：
摘要解析、入队、计数。GUI 主线程用 100 ms 定时器批量取走队列，
一次性刷新表格，从而把“高频抓包”与“低频重绘”解耦。
"""

from __future__ import annotations

import os
import platform
import queue
import time
from dataclasses import dataclass, field
from typing import Optional

from PySide6.QtCore import QObject, QTimer, Signal

from .dissector import dissect
from .models import PacketRecord

# Windows 下 Npcap 安装后必然存在的驱动文件
_NPCAP_SYS = r"C:\Windows\System32\drivers\npcap.sys"

# 这些是 NDIS 过滤驱动生成的伪设备，无法独立抓包
_PSEUDO_KEYWORDS = (
    "LightWeight Filter", "QoS Packet Scheduler", "WFP ",
    "Virtual WiFi Filter", "Scheduler-0000", "Filter-0000",
)


def npcap_ready() -> tuple[bool, str]:
    """检查 Npcap 驱动是否真正可用（仅 Windows）。"""
    if platform.system() != "Windows":
        return True, ""
    if os.path.exists(_NPCAP_SYS):
        return True, ""
    return False, (
        "未检测到 Npcap 驱动（C:\\Windows\\System32\\drivers\\npcap.sys 不存在）。\n\n"
        "请安装 Npcap：https://npcap.com\n"
        "安装向导弹出时务必完成全部步骤，并勾选：\n"
        "    Install Npcap in WinPcap API-compatible Mode\n"
        "安装完成后重新启动本程序，并以管理员身份运行。"
    )


@dataclass(slots=True)
class Interface:
    name: str
    device: str
    description: str = ""
    ips: list[str] = field(default_factory=list)
    mac: str = ""

    @property
    def display(self) -> str:
        ips = ", ".join(self.ips) if self.ips else "无地址"
        return f"{self.name}  [{ips}]"


def list_interfaces() -> list[Interface]:
    """枚举可抓包的网卡（Windows 下返回 NPF 设备名）。"""
    result: list[Interface] = []
    if platform.system() == "Windows":
        try:
            from scapy.arch.windows import get_windows_if_list

            try:
                items = get_windows_if_list(include_loopback=True)
            except TypeError:
                items = get_windows_if_list()
            for item in items:
                guid = item.get("guid") or ""
                device = f"\\Device\\NPF_{guid}" if guid else ""
                if not device:
                    continue
                name = item.get("description") or item.get("name") or "unknown"
                if any(keyword.lower() in name.lower() for keyword in _PSEUDO_KEYWORDS):
                    continue
                ips = [ip for ip in (item.get("ips") or []) if ip and not ip.startswith("fe80")]
                mac = item.get("mac") or ""
                if not ips and not mac:
                    continue
                result.append(
                    Interface(
                        name=name,
                        device=device,
                        description=item.get("name") or "",
                        ips=ips,
                        mac=mac,
                    )
                )
        except Exception:
            result = []

    if not result:
        try:
            from scapy.all import get_if_addr, get_if_list

            for name in get_if_list():
                try:
                    ip = get_if_addr(name)
                except Exception:
                    ip = ""
                result.append(Interface(name=name, device=name, ips=[ip] if ip else []))
        except Exception:
            result = []

    # 过滤掉明显不可用的条目（无 GUID 的伪设备）
    return [iface for iface in result if iface.device]


class CaptureController(QObject):
    """封装 AsyncSniffer 的生命周期，并通过信号把报文交给 GUI。"""

    packetsReady = Signal(list)
    errorOccurred = Signal(str)
    started = Signal()
    stopped = Signal()

    DRAIN_INTERVAL_MS = 100
    MAX_PENDING = 200_000

    def __init__(self, parent: Optional[QObject] = None):
        super().__init__(parent)
        self._sniffer = None
        self._queue: queue.Queue[PacketRecord] = queue.Queue()
        self._timer = QTimer(self)
        self._timer.setInterval(self.DRAIN_INTERVAL_MS)
        self._timer.timeout.connect(self._drain)

        self.captured = 0
        self.dropped = 0
        self._pending = 0
        self._seq = 0
        self._started_at = 0.0
        self._recent: list[tuple[float, int]] = []

    # ------------------------------------------------------------ 状态

    @property
    def running(self) -> bool:
        return self._sniffer is not None and getattr(self._sniffer, "running", False)

    def stats(self) -> dict:
        elapsed = max(1e-6, (time.time() - self._started_at)) if self._started_at else 0.0
        now = time.time()
        self._recent = [(t, n) for (t, n) in self._recent if now - t <= 1.0]
        rate = sum(n for _, n in self._recent)
        return {
            "captured": self.captured,
            "dropped": self.dropped,
            "pending": self._pending,
            "elapsed": elapsed,
            "rate": rate,
        }

    # ------------------------------------------------------------ 控制

    def start(self, device: str, bpf_filter: str = "", promisc: bool = True,
              snaplen: int = 262144) -> bool:
        if self.running:
            return False
        try:
            from scapy.sendrecv import AsyncSniffer
        except Exception as exc:  # pragma: no cover
            self.errorOccurred.emit(f"Scapy 初始化失败：{exc}")
            return False

        filter_text = (bpf_filter or "").strip() or None
        try:
            self._sniffer = AsyncSniffer(
                iface=device,
                filter=filter_text,
                prn=self._on_packet,
                store=False,
                promisc=promisc,
            )
            self._sniffer.start()
        except Exception as exc:
            self._sniffer = None
            self.errorOccurred.emit(self._explain_error(exc))
            return False

        # AsyncSniffer 在线程中启动，稍等片刻以捕获 BPF 语法错误等异常
        deadline = time.time() + 1.5
        while time.time() < deadline:
            if self._sniffer.exception is not None:
                exc = self._sniffer.exception
                self._sniffer = None
                self.errorOccurred.emit(self._explain_error(exc))
                return False
            if getattr(self._sniffer, "running", False):
                break
            time.sleep(0.02)

        if self._sniffer is None:
            self.errorOccurred.emit("抓包启动失败")
            return False

        self.captured = 0
        self.dropped = 0
        self._pending = 0
        self._seq = 0
        self._recent.clear()
        self._started_at = time.time()
        self._timer.start()
        self.started.emit()
        return True

    def stop(self) -> None:
        self._timer.stop()
        sniffer = self._sniffer
        self._sniffer = None
        if sniffer is not None:
            try:
                sniffer.stop()
            except Exception:
                pass
        self._drain()
        self.stopped.emit()

    # ------------------------------------------------------------ 内部

    @staticmethod
    def _explain_error(exc: BaseException) -> str:
        text = str(exc)
        if "filter" in text.lower() and ("syntax" in text.lower() or "compile" in text.lower()):
            return f"BPF 过滤表达式非法：{text}"
        if "permission" in text.lower() or "access is denied" in text.lower():
            return "权限不足：抓包需要管理员权限，且需已安装 Npcap。"
        if "npcap" in text.lower() or "wpcap" in text.lower():
            return "未找到 Npcap：请安装 https://npcap.com 并勾选 WinPcap API 兼容模式。"
        return f"抓包失败：{text}"

    def _on_packet(self, pkt) -> None:
        try:
            self._seq += 1
            ts = float(getattr(pkt, "time", time.time()))
            data = bytes(pkt)
            record = dissect(data, ts, self._seq)
            if self._pending >= self.MAX_PENDING:
                self.dropped += 1
                return
            self._pending += 1
            self._queue.put(record)
        except Exception:
            self.dropped += 1

    def _drain(self) -> None:
        batch: list[PacketRecord] = []
        while True:
            try:
                batch.append(self._queue.get_nowait())
            except queue.Empty:
                break
            if len(batch) >= 5000:
                break
        if not batch:
            return
        self._pending = max(0, self._pending - len(batch))
        self.captured += len(batch)
        now = time.time()
        self._recent.append((now, len(batch)))
        self.packetsReady.emit(batch)
