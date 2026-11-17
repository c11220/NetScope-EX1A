"""协议详情树：把 OSI 每一层展开成可折叠的字段树。"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import QAbstractItemView, QTreeWidget, QTreeWidgetItem

from ..core.dissector import build_tree
from ..core.models import PacketRecord, TreeNode
from . import theme


class DetailTree(QTreeWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setColumnCount(2)
        self.setHeaderLabels(["字段", "值"])
        self.setAlternatingRowColors(False)
        self.setRootIsDecorated(True)
        self.setUniformRowHeights(True)
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.setAnimated(True)
        self.header().setStretchLastSection(True)
        self.setColumnWidth(0, 430)

        self._mono = QFont("Cascadia Mono")
        self._mono.setStyleHint(QFont.Monospace)
        self._mono.setPointSize(9)

    def show_record(self, record: PacketRecord) -> None:
        self.clear()
        if record is None:
            return
        root = build_tree(record)
        self._add_node(self, root, depth=0)
        self.expandToDepth(1)

    def clear_record(self) -> None:
        self.clear()

    def _add_node(self, parent, node: TreeNode, depth: int) -> QTreeWidgetItem:
        item = QTreeWidgetItem([node.label, node.value])
        item.setFont(0, self._mono)
        item.setFont(1, self._mono)
        if depth == 0:
            item.setForeground(0, QColor(theme.COLORS["accent"]))
        elif node.value:
            item.setForeground(0, QColor("#c9d2dd"))
            item.setForeground(1, QColor("#8ecdd6"))
        if isinstance(parent, QTreeWidgetItem):
            parent.addChild(item)
        else:
            parent.addTopLevelItem(item)
        for child in node.children:
            self._add_node(item, child, depth + 1)
        return item

    def keyPressEvent(self, event):
        if event.matches(event.StandardKey.Copy):
            items = self.selectedItems()
            if items:
                parts = []
                node = items[0]
                while node is not None:
                    parts.append(f"{node.text(0)}" + (f": {node.text(1)}" if node.text(1) else ""))
                    node = node.parent()
                from PySide6.QtWidgets import QApplication

                QApplication.clipboard().setText(" / ".join(reversed(parts)))
            return
        super().keyPressEvent(event)
