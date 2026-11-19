"""在真实网卡上抓包并截图（用于报告中的“实时抓包”证据）。

用法（管理员权限更稳妥）：
    python tools/live_capture_shot.py [秒数]
"""

from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from PySide6.QtCore import QTimer                  # noqa: E402
from PySide6.QtGui import QFont                    # noqa: E402
from PySide6.QtWidgets import QApplication         # noqa: E402

from app.ui.dialogs import StatisticsDialog        # noqa: E402
from app.ui.main_window import MainWindow          # noqa: E402
from app.ui.theme import stylesheet                # noqa: E402

ASSETS = os.path.join(ROOT, "report", "assets")
SECONDS = int(sys.argv[1]) if len(sys.argv) > 1 else 8


def main() -> int:
    os.makedirs(ASSETS, exist_ok=True)
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setFont(QFont("Microsoft YaHei UI", 9))
    app.setStyleSheet(stylesheet())

    window = MainWindow()
    window.resize(1460, 900)
    window.show()
    app.processEvents()

    # 选择有全局地址的网卡（跳过 169.254 与回环）
    for index in range(window.iface_combo.count()):
        device = window.iface_combo.itemData(index)
        text = window.iface_combo.itemText(index)
        if "169.254" in text or "Loopback" in text:
            continue
        window.iface_combo.setCurrentIndex(index)
        break

    window.filter_edit.setText("tls or http")
    window._apply_display_filter()
    window.capture_filter.setText("tcp port 443 or tcp port 80")

    QTimer.singleShot(300, window._start_capture)

    def finish():
        window._stop_capture()
        app.processEvents()
        window.filter_edit.setText("")
        window._apply_display_filter()
        rows = window.model.rowCount()
        if rows:
            window.table.selectRow(max(0, rows - 3))
            window.table.scrollToBottom()
        app.processEvents()
        window.grab().save(os.path.join(ASSETS, "07_live_capture.png"))
        print("captured", window.stats.total, "packets")

        dialog = StatisticsDialog(window.stats)
        dialog.resize(980, 620)
        dialog.show()
        app.processEvents()
        dialog.grab().save(os.path.join(ASSETS, "08_live_stats.png"))
        dialog.close()

        app.quit()

    QTimer.singleShot(SECONDS * 1000, finish)
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
