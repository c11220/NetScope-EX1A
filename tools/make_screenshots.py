"""用离屏渲染生成报告所需的界面截图。

用法：``python tools/make_screenshots.py``
输出到 ``report/assets/``。
"""

from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from PySide6.QtGui import QFont                     # noqa: E402
from PySide6.QtWidgets import QApplication          # noqa: E402

from app.ui.dialogs import FilterSyntaxDialog, FlowsDialog, StatisticsDialog  # noqa: E402
from app.ui.main_window import MainWindow            # noqa: E402
from app.ui.theme import stylesheet                 # noqa: E402

OUT = os.path.join(ROOT, "report", "assets")


def snap(widget, name: str) -> str:
    path = os.path.join(OUT, name)
    widget.grab().save(path)
    print("saved", path)
    return path


def main() -> None:
    os.makedirs(OUT, exist_ok=True)

    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setFont(QFont("Microsoft YaHei UI", 9))
    app.setStyleSheet(stylesheet())

    window = MainWindow()
    window.resize(1460, 900)
    window.show()
    app.processEvents()

    pcap = os.path.join(ROOT, "demo", "demo.pcap")
    window.load_path_sync(pcap)
    app.processEvents()

    # 选中一条 HTTP GET 报文，让协议详情与十六进制都有内容
    target_row = 0
    for row in range(window.model.rowCount()):
        record = window.model.record_at(row)
        if record and record.proto == "HTTP" and record.info.startswith("GET"):
            target_row = row
            break
    window.table.selectRow(target_row)
    app.processEvents()

    snap(window, "01_main_http.png")

    # 显示过滤器演示
    window.filter_edit.setText("http or dns")
    window._apply_display_filter()
    app.processEvents()
    snap(window, "02_display_filter.png")

    # 仅看 TLS/SNI
    window.filter_edit.setText('tls and tls.sni contains "github"')
    window._apply_display_filter()
    app.processEvents()
    snap(window, "03_tls_filter.png")

    # 统计对话框
    stats_dialog = StatisticsDialog(window.stats)
    stats_dialog.resize(980, 620)
    stats_dialog.show()
    app.processEvents()
    snap(stats_dialog, "04_statistics.png")
    stats_dialog.close()

    # 流追踪对话框
    streams = sorted(window.flows.tracker.streams(), key=lambda s: -s.packets)
    flows_dialog = FlowsDialog(streams)
    flows_dialog.resize(1100, 700)
    flows_dialog.show()
    app.processEvents()
    snap(flows_dialog, "05_flows.png")
    flows_dialog.close()

    # 过滤器语法帮助
    syntax = FilterSyntaxDialog()
    syntax.resize(760, 640)
    syntax.show()
    app.processEvents()
    snap(syntax, "06_filter_syntax.png")
    syntax.close()

    window.close()


if __name__ == "__main__":
    main()
