"""报文列表的 Qt 数据模型（QAbstractTableModel）。

为了在数万行规模下仍然流畅，模型内部维护两份索引：
``_records``（全部报文）与 ``_visible``（通过显示过滤器的下标）。
插入时只对新增行做过滤，避免整表重建。
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt, QObject
from PySide6.QtGui import QColor, QFont

from ..core.filter_engine import DisplayFilter
from ..core.models import PacketRecord
from . import theme

HEADERS = ["序号", "时间", "源地址", "目的地址", "协议", "长度", "流", "进程", "信息"]

COL_INDEX, COL_TIME, COL_SRC, COL_DST, COL_PROTO, COL_LEN, COL_FLOW, COL_PROC, COL_INFO = range(9)


class PacketTableModel(QAbstractTableModel):
    MAX_RECORDS = 300_000

    def __init__(self, parent: Optional[QObject] = None):
        super().__init__(parent)
        self._records: list[PacketRecord] = []
        self._visible: list[int] = []
        self._filter: Optional[DisplayFilter] = None
        self._mono = QFont("Cascadia Mono")
        self._mono.setStyleHint(QFont.Monospace)
        self._mono.setPointSize(9)

    # ------------------------------------------------------------ Qt 接口

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._visible)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(HEADERS)

    def headerData(self, section: int, orientation: Qt.Orientation,
                   role: int = Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return HEADERS[section]
        return None

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole):
        if not index.isValid():
            return None
        record = self.record_at(index.row())
        if record is None:
            return None
        column = index.column()

        if role == Qt.DisplayRole:
            if column == COL_INDEX:
                return record.index
            if column == COL_TIME:
                return record.time_text
            if column == COL_SRC:
                return record.src_endpoint()
            if column == COL_DST:
                return record.dst_endpoint()
            if column == COL_PROTO:
                return record.proto
            if column == COL_LEN:
                return record.length
            if column == COL_FLOW:
                return f"#{record.flow_no}" if record.flow_no is not None else ""
            if column == COL_PROC:
                return record.pname or ""
            if column == COL_INFO:
                return record.info
            return ""

        if role == Qt.ForegroundRole:
            if column == COL_PROTO:
                return theme.color_for(record.proto)
            if column == COL_PROC:
                return QColor(theme.COLORS["muted"])
            if column == COL_INFO:
                return QColor("#c3c9d1")
            return None

        if role == Qt.TextAlignmentRole:
            if column in (COL_INDEX, COL_LEN):
                return int(Qt.AlignRight | Qt.AlignVCenter)
            if column == COL_FLOW:
                return int(Qt.AlignCenter)
            return int(Qt.AlignLeft | Qt.AlignVCenter)

        if role == Qt.FontRole:
            if column == COL_PROTO:
                font = QFont(self._mono)
                font.setBold(True)
                return font
            return None

        if role == Qt.ToolTipRole:
            return (f"Frame {record.index}\n{record.src_endpoint()} → {record.dst_endpoint()}\n"
                    f"{record.proto}  {record.length} bytes\n{record.info}")

        return None

    # ------------------------------------------------------------ 业务方法

    def record_at(self, row: int) -> Optional[PacketRecord]:
        if 0 <= row < len(self._visible):
            return self._records[self._visible[row]]
        return None

    def all_records(self) -> list[PacketRecord]:
        return self._records

    def visible_records(self) -> list[PacketRecord]:
        return [self._records[i] for i in self._visible]

    def visible_count(self) -> int:
        return len(self._visible)

    def add_records(self, records: list[PacketRecord]) -> None:
        if not records:
            return
        if len(self._records) >= self.MAX_RECORDS:
            records = records[: max(0, self.MAX_RECORDS - len(self._records))]
            if not records:
                return
        start = len(self._records)
        self._records.extend(records)

        new_visible: list[int] = []
        for offset, record in enumerate(records):
            if self._filter is None or self._filter.match(record):
                new_visible.append(start + offset)
        if not new_visible:
            return

        first = len(self._visible)
        self.beginInsertRows(QModelIndex(), first, first + len(new_visible) - 1)
        self._visible.extend(new_visible)
        self.endInsertRows()

    def set_filter(self, new_filter: Optional[DisplayFilter]) -> None:
        self._filter = new_filter
        self.beginResetModel()
        if new_filter is None or new_filter.is_empty:
            self._visible = list(range(len(self._records)))
        else:
            self._visible = [i for i, rec in enumerate(self._records) if new_filter.match(rec)]
        self.endResetModel()

    def clear(self) -> None:
        self.beginResetModel()
        self._records.clear()
        self._visible.clear()
        self.endResetModel()

    def locate(self, record: PacketRecord) -> int:
        """返回某条报文当前可见行号，找不到返回 -1。"""
        idx = self._records.index(record)
        try:
            return self._visible.index(idx)
        except ValueError:
            return -1
