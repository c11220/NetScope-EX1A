"""实时抓包自检：验证 Npcap 驱动、网卡与 BPF 过滤是否可用。

用法（请以管理员身份运行）：
    python tools/verify_live.py            # 使用第一块网卡抓 6 秒
    set EX1A_IFACE=\\Device\\NPF_{GUID}     # 指定网卡
    python tools\\verify_live.py
"""

from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from PySide6.QtCore import QCoreApplication, QTimer  # noqa: E402

from app.core.capture import CaptureController, list_interfaces, npcap_ready  # noqa: E402

SECONDS = int(os.environ.get("EX1A_SECONDS", "6"))


def main() -> int:
    ready, reason = npcap_ready()
    print(f"[0] Npcap 驱动：{'正常' if ready else '未安装'}")
    if not ready:
        print(reason)
        return 1

    ifaces = list_interfaces()
    print(f"[1] 发现网卡 {len(ifaces)} 块")
    for iface in ifaces[:12]:
        print(f"    - {iface.name}  {iface.ips}  {iface.device}")

    if not ifaces:
        print("[!] 没有可用网卡：请确认 Npcap 已安装")
        return 1

    device = os.environ.get("EX1A_IFACE") or ifaces[0].device
    app = QCoreApplication(sys.argv)
    controller = CaptureController()
    counter = {"n": 0}

    def on_batch(records):
        counter["n"] += len(records)
        for rec in records[:3]:
            print(f"    #{rec.index} {rec.proto:6s} {rec.src_endpoint():22s} -> "
                  f"{rec.dst_endpoint():22s} {rec.info[:60]}")

    def on_error(message):
        print("[!] 抓包错误：", message)
        app.quit()

    controller.packetsReady.connect(on_batch)
    controller.errorOccurred.connect(on_error)

    ok = controller.start(device, os.environ.get("EX1A_BPF", ""), True)
    print(f"[2] 启动抓包：{'成功' if ok else '失败'}  设备={device}")
    if not ok:
        return 2

    print(f"[3] 请产生一些网络流量，抓取 {SECONDS} 秒…")
    QTimer.singleShot(SECONDS * 1000, lambda: (controller.stop(), app.quit()))
    app.exec()

    stats = controller.stats()
    print(f"[4] 结果：捕获 {counter['n']} 包，丢弃 {stats['dropped']}")
    if counter["n"] == 0:
        print("[!] 未捕获到任何报文：可能是权限不足、网卡选错或确实无流量")
        return 3
    print("[OK] 实时抓包验证通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
