"""进程归因：把 TCP/UDP 连接映射到产生它的本地进程（CommView 的进程视图）。

Npcap 只给出“包”，不给出“谁发的包”。这里用 psutil 周期性快照
``net_connections()``，建立 (本地地址, 本地端口) → (pid, 进程名) 的索引，
再对每个报文反查本地端，从而支持“某进程产生的所有 TCP 流”。
"""

from __future__ import annotations

import threading
import time
from typing import Optional

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None


class ProcessResolver:
    def __init__(self, refresh_interval: float = 2.0):
        self._interval = refresh_interval
        self._lock = threading.Lock()
        self._tcp: dict[tuple[str, int], tuple[int, str]] = {}
        self._udp: dict[tuple[str, int], tuple[int, str]] = {}
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    # ------------------------------------------------------------ 生命周期

    def start(self) -> None:
        if psutil is None or self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="proc-resolver", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            self.refresh()
            self._stop.wait(self._interval)

    # ------------------------------------------------------------ 刷新

    def refresh(self) -> None:
        if psutil is None:
            return
        tcp: dict[tuple[str, int], tuple[int, str]] = {}
        udp: dict[tuple[str, int], tuple[int, str]] = {}
        try:
            conns = psutil.net_connections(kind="inet")
        except Exception:
            return
        for conn in conns:
            if conn.pid is None or conn.laddr is None:
                continue
            try:
                name = psutil.Process(conn.pid).name()
            except Exception:
                name = f"pid-{conn.pid}"
            key = (conn.laddr.ip, conn.laddr.port)
            target = tcp if conn.type == 1 else udp  # SOCK_STREAM / SOCK_DGRAM
            target[key] = (conn.pid, name)
        with self._lock:
            self._tcp, self._udp = tcp, udp

    # ------------------------------------------------------------ 查询

    def lookup(self, proto: str, src: str, dst: str, sport: Optional[int],
               dport: Optional[int]) -> tuple[Optional[int], str]:
        if psutil is None or sport is None:
            return None, ""
        with self._lock:
            table = self._tcp if proto.upper().startswith("TCP") else self._udp
            for ip, port in ((src, sport), (dst, dport)):
                if port is None:
                    continue
                hit = table.get((ip, port))
                if hit:
                    return hit
        return None, ""
