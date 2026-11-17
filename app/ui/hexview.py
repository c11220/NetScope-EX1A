"""十六进制视图：以 Wireshark 风格展示原始字节。"""

from __future__ import annotations

from PySide6.QtCore import QRect, Qt
from PySide6.QtGui import QColor, QFont, QPainter
from PySide6.QtWidgets import QAbstractScrollArea

from . import theme

_BYTES_PER_LINE = 16


class HexView(QAbstractScrollArea):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._data = b""
        self._font = QFont("Cascadia Mono")
        self._font.setStyleHint(QFont.Monospace)
        self._font.setPointSize(9)
        self.setFont(self._font)
        self.setFrameShape(QAbstractScrollArea.NoFrame)
        self.viewport().setAutoFillBackground(True)
        self.verticalScrollBar().valueChanged.connect(self.viewport().update)
        self._line_height = self.fontMetrics().height() + 3

    # ------------------------------------------------------------ 数据

    def set_data(self, data: bytes) -> None:
        self._data = data or b""
        self._update_scrollbar()
        self.viewport().update()

    def _update_scrollbar(self) -> None:
        lines = (len(self._data) + _BYTES_PER_LINE - 1) // _BYTES_PER_LINE
        viewport_height = max(1, self.viewport().height())
        visible = max(1, viewport_height // self._line_height)
        self.verticalScrollBar().setRange(0, max(0, lines - visible))
        self.verticalScrollBar().setPageStep(visible)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._line_height = self.fontMetrics().height() + 3
        self._update_scrollbar()

    # ------------------------------------------------------------ 绘制

    def paintEvent(self, event):
        painter = QPainter(self.viewport())
        painter.setFont(self._font)
        metrics = painter.fontMetrics()

        bg = QColor(theme.COLORS["bg"])
        painter.fillRect(self.viewport().rect(), bg)

        if not self._data:
            painter.setPen(QColor(theme.COLORS["muted"]))
            painter.drawText(12, metrics.ascent() + 10, "选中一条报文以查看其原始字节")
            painter.end()
            return

        offset_width = metrics.horizontalAdvance("0000") + 14
        hex_width = metrics.horizontalAdvance("00 ") * 8 + 12
        y = metrics.ascent() + 6

        first = self.verticalScrollBar().value()
        total_lines = (len(self._data) + _BYTES_PER_LINE - 1) // _BYTES_PER_LINE
        rows = self.viewport().height() // self._line_height + 2

        offset_color = QColor(theme.COLORS["muted"])
        hex_color = QColor("#cfd5dd")
        zero_color = QColor("#5a616a")
        ascii_color = QColor("#8ecdd6")

        for line in range(first, min(total_lines, first + rows)):
            base = line * _BYTES_PER_LINE
            chunk = self._data[base:base + _BYTES_PER_LINE]
            painter.setPen(offset_color)
            painter.drawText(4, y, f"{base:04x}")

            hex_x = offset_width
            for i, byte in enumerate(chunk):
                painter.setPen(zero_color if byte == 0 else hex_color)
                # 每 8 字节插入一个分隔
                extra = 6 if i >= 8 else 0
                painter.drawText(hex_x + i * metrics.horizontalAdvance("00 ") + extra, y, f"{byte:02x}")

            ascii_x = offset_width + hex_width
            text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            painter.setPen(ascii_color)
            painter.drawText(ascii_x, y, text)

            if base + _BYTES_PER_LINE < len(self._data):
                painter.setPen(QColor("#2c3036"))
                painter.drawLine(0, y + 4, self.viewport().width(), y + 4)

            y += self._line_height

        painter.end()
