"""NetScope —— 带 GUI 的网络嗅探器（实验 1A）。

入口：``python main.py``，可附加一个 pcap 路径直接离线分析。
"""

from __future__ import annotations

import os
import sys

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QApplication

from app.ui.main_window import MainWindow
from app.ui.theme import stylesheet

APP_NAME = "NetScope"
VERSION = "1.0.0"


def main() -> int:
    QApplication.setApplicationName(APP_NAME)
    QApplication.setApplicationVersion(VERSION)

    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setFont(QFont("Microsoft YaHei UI", 9))
    app.setStyleSheet(stylesheet())

    window = MainWindow()
    window.show()

    if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
        window.load_path_sync(sys.argv[1])

    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
