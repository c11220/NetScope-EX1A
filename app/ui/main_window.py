"""主窗口：三栏式嗅探器界面（报文列表 / 协议详情 / 十六进制）。"""

from __future__ import annotations

import os
import time
from typing import Optional

from PySide6.QtCore import QObject, Qt, QThread, QTimer, Signal
from PySide6.QtGui import QAction, QColor, QIcon, QKeySequence, QPixmap
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QFileDialog, QFrame, QHBoxLayout,
    QHeaderView, QLabel, QLineEdit, QMainWindow, QMessageBox, QProgressDialog,
    QPushButton, QSplitter, QStatusBar, QTabWidget, QTableView, QVBoxLayout,
    QWidget,
)

from ..core.capture import CaptureController, Interface, list_interfaces
from ..core.filter_engine import DisplayFilter, FilterSyntaxError, validate
from ..core.flows import FlowRegistry
from ..core.pcap_io import load_pcap, save_pcap
from ..core.proc_map import ProcessResolver
from ..core.stats import StatsCollector
from . import theme
from .detail_tree import DetailTree
from .dialogs import AboutDialog, FilterSyntaxDialog, FlowsDialog, StatisticsDialog
from .hexview import HexView
from .packet_model import (
    COL_INFO, COL_PROTO, PacketTableModel,
)

PRESET_FILTERS = [
    ("常用显示过滤器…", ""),
    ("仅 TCP", "tcp"),
    ("仅 UDP", "udp"),
    ("HTTP 流量", "http"),
    ("DNS 查询", "dns"),
    ("TLS / HTTPS", "tls"),
    ("ICMP 与 ARP", "icmp or arp"),
    ("IPv6 流量", "ipv6"),
    ("排除本机回环噪声", "not port 22 and not port 445"),
    ("大包 (>800B)", "frame.len > 800"),
]


class _LoadWorker(QThread):
    finishedLoading = Signal(list, int)
    failed = Signal(str)

    def __init__(self, path: str, parent=None):
        super().__init__(parent)
        self._path = path

    def run(self) -> None:
        try:
            records, linktype = load_pcap(self._path)
            self.finishedLoading.emit(records, linktype)
        except Exception as exc:
            self.failed.emit(str(exc))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetScope · 网络嗅探与协议分析器  |  实验 1A")
        self.resize(1400, 860)

        self.model = PacketTableModel(self)
        self.stats = StatsCollector()
        self.flows = FlowRegistry()
        self.resolver = ProcessResolver()
        self.capture = CaptureController(self)
        self._follow_tail = True
        self._ifaces: list[Interface] = []
        self._load_worker: Optional[_LoadWorker] = None
        self._display_filter: Optional[DisplayFilter] = None

        self._build_ui()
        self._build_menu()
        self._connect()
        self._refresh_interfaces()

        self.resolver.start()
        self._status_timer = QTimer(self)
        self._status_timer.setInterval(500)
        self._status_timer.timeout.connect(self._tick)
        self._status_timer.start()

        self.statusBar().showMessage("就绪：请选择网卡并点击“开始捕获”，或打开一个 pcap 文件", 6000)

    # ================================================================ UI

    def _build_ui(self) -> None:
        central = QWidget()
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_toolbar())
        root.addWidget(self._build_filter_bar())

        splitter = QSplitter(Qt.Vertical)
        splitter.setChildrenCollapsible(False)
        root.addWidget(splitter, 1)

        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(22)
        self.table.setWordWrap(False)
        self.table.horizontalHeader().setHighlightSections(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        widths = {0: 78, 1: 104, 2: 176, 3: 176, 4: 76, 5: 62, 6: 54, 7: 118}
        for column, width in widths.items():
            self.table.setColumnWidth(column, width)
        splitter.addWidget(self.table)

        self.detail_tabs = QTabWidget()
        self.detail_tabs.setDocumentMode(True)
        self.tree = DetailTree()
        self.hexview = HexView()
        self.detail_tabs.addTab(self.tree, "协议详情")
        self.detail_tabs.addTab(self.hexview, "十六进制")
        splitter.addWidget(self.detail_tabs)
        splitter.setSizes([520, 320])

        self.setCentralWidget(central)

        status = QStatusBar()
        status.setSizeGripEnabled(True)
        self.setStatusBar(status)
        self.lbl_state = QLabel("● 空闲")
        self.lbl_state.setStyleSheet(f"color:{theme.COLORS['muted']}")
        self.lbl_counts = QLabel("报文 0")
        self.lbl_shown = QLabel("显示 0")
        self.lbl_rate = QLabel("0 包/秒")
        self.lbl_drops = QLabel("丢弃 0")
        for widget in (self.lbl_state, self.lbl_counts, self.lbl_shown, self.lbl_rate, self.lbl_drops):
            widget.setObjectName("Hint")
            status.addPermanentWidget(widget)

    def _build_toolbar(self) -> QWidget:
        bar = QFrame()
        bar.setObjectName("Toolbar")
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(8)

        label = QLabel("网卡")
        layout.addWidget(label)
        self.iface_combo = QComboBox()
        self.iface_combo.setMinimumWidth(360)
        self.iface_combo.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        layout.addWidget(self.iface_combo, 1)

        self.btn_refresh = QPushButton("刷新")
        self.btn_refresh.setToolTip("重新枚举网卡")
        layout.addWidget(self.btn_refresh)

        self.chk_promisc = QCheckBox("混杂模式")
        self.chk_promisc.setChecked(True)
        self.chk_promisc.setToolTip("接收经过网卡的所有帧，而不只是发给本机的帧")
        layout.addWidget(self.chk_promisc)

        self.btn_start = QPushButton("● 开始捕获")
        self.btn_start.setObjectName("Primary")
        self.btn_start.setShortcut(QKeySequence("F5"))
        layout.addWidget(self.btn_start)

        self.btn_stop = QPushButton("■ 停止")
        self.btn_stop.setObjectName("Danger")
        self.btn_stop.setEnabled(False)
        layout.addWidget(self.btn_stop)

        layout.addSpacing(12)
        self.chk_follow = QCheckBox("跟随最新")
        self.chk_follow.setChecked(True)
        self.chk_follow.setToolTip("自动滚动到最新的报文")
        layout.addWidget(self.chk_follow)

        return bar

    def _build_filter_bar(self) -> QWidget:
        bar = QFrame()
        bar.setObjectName("FilterBar")
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(12, 6, 12, 6)
        layout.setSpacing(8)

        layout.addWidget(QLabel("BPF 捕获过滤"))
        self.capture_filter = QLineEdit()
        self.capture_filter.setPlaceholderText("如 tcp port 80，留空表示全部")
        self.capture_filter.setFixedWidth(240)
        self.capture_filter.setToolTip("在 Npcap 内核态生效，语法见 pcap-filter(7)")
        layout.addWidget(self.capture_filter)

        layout.addSpacing(10)
        layout.addWidget(QLabel("显示过滤器"))
        self.filter_edit = QLineEdit()
        self.filter_edit.setObjectName("Filter")
        self.filter_edit.setPlaceholderText(
            '如 http and http.host contains "ucas"，支持 and/or/not 与括号'
        )
        self.filter_edit.setClearButtonEnabled(True)
        layout.addWidget(self.filter_edit, 1)

        self.btn_apply_filter = QPushButton("应用")
        layout.addWidget(self.btn_apply_filter)

        self.preset_combo = QComboBox()
        for name, _expr in PRESET_FILTERS:
            self.preset_combo.addItem(name)
        self.preset_combo.setFixedWidth(150)
        layout.addWidget(self.preset_combo)

        self.btn_clear = QPushButton("清空列表")
        layout.addWidget(self.btn_clear)

        return bar

    def _build_menu(self) -> None:
        menubar = self.menuBar()

        file_menu = menubar.addMenu("文件(&F)")
        self.act_open = QAction("打开 pcap…", self)
        self.act_open.setShortcut(QKeySequence.Open)
        self.act_open.triggered.connect(self._open_pcap)
        file_menu.addAction(self.act_open)

        self.act_save = QAction("保存为 pcap…", self)
        self.act_save.setShortcut(QKeySequence.Save)
        self.act_save.triggered.connect(self._save_pcap)
        file_menu.addAction(self.act_save)
        file_menu.addSeparator()

        act_quit = QAction("退出", self)
        act_quit.setShortcut(QKeySequence.Quit)
        act_quit.triggered.connect(self.close)
        file_menu.addAction(act_quit)

        cap_menu = menubar.addMenu("捕获(&C)")
        self.act_start = QAction("开始捕获", self)
        self.act_start.setShortcut(QKeySequence("F5"))
        self.act_start.triggered.connect(self._start_capture)
        cap_menu.addAction(self.act_start)

        self.act_stop = QAction("停止捕获", self)
        self.act_stop.setShortcut(QKeySequence("Shift+F5"))
        self.act_stop.triggered.connect(self._stop_capture)
        self.act_stop.setEnabled(False)
        cap_menu.addAction(self.act_stop)

        cap_menu.addSeparator()
        act_clear = QAction("清空列表", self)
        act_clear.setShortcut(QKeySequence("Ctrl+L"))
        act_clear.triggered.connect(self._clear)
        cap_menu.addAction(act_clear)

        analyze_menu = menubar.addMenu("分析(&A)")
        act_stats = QAction("协议分层统计…", self)
        act_stats.setShortcut(QKeySequence("Ctrl+T"))
        act_stats.triggered.connect(self._show_stats)
        analyze_menu.addAction(act_stats)

        act_flows = QAction("TCP 流追踪…", self)
        act_flows.setShortcut(QKeySequence("Ctrl+F"))
        act_flows.triggered.connect(self._show_flows)
        analyze_menu.addAction(act_flows)

        act_current_flow = QAction("查看当前报文所属流", self)
        act_current_flow.triggered.connect(self._show_current_flow)
        analyze_menu.addAction(act_current_flow)

        help_menu = menubar.addMenu("帮助(&H)")
        act_syntax = QAction("显示过滤器语法", self)
        act_syntax.setShortcut(QKeySequence("F1"))
        act_syntax.triggered.connect(lambda: FilterSyntaxDialog(self).exec())
        help_menu.addAction(act_syntax)

        act_about = QAction("关于 NetScope", self)
        act_about.triggered.connect(lambda: AboutDialog(self).exec())
        help_menu.addAction(act_about)

    def _connect(self) -> None:
        self.btn_start.clicked.connect(self._start_capture)
        self.btn_stop.clicked.connect(self._stop_capture)
        self.btn_refresh.clicked.connect(self._refresh_interfaces)
        self.btn_apply_filter.clicked.connect(self._apply_display_filter)
        self.btn_clear.clicked.connect(self._clear)
        self.filter_edit.returnPressed.connect(self._apply_display_filter)
        self.preset_combo.activated.connect(self._apply_preset)
        self.filter_edit.textChanged.connect(self._validate_filter_ui)
        self.chk_follow.toggled.connect(lambda value: setattr(self, "_follow_tail", value))

        self.capture.packetsReady.connect(self._on_packets)
        self.capture.started.connect(self._on_capture_started)
        self.capture.stopped.connect(self._on_capture_stopped)
        self.capture.errorOccurred.connect(self._on_capture_error)

        self.table.selectionModel().currentRowChanged.connect(self._on_row_changed)

    # ============================================================ 网卡列表

    def _refresh_interfaces(self) -> None:
        self._ifaces = list_interfaces()
        current = self.iface_combo.currentData()
        self.iface_combo.clear()
        for iface in self._ifaces:
            self.iface_combo.addItem(iface.display, iface.device)
        if current:
            index = self.iface_combo.findData(current)
            if index >= 0:
                self.iface_combo.setCurrentIndex(index)
        if not self._ifaces:
            self.iface_combo.addItem("未发现可用网卡（请安装 Npcap）", "")

    # ============================================================ 抓包控制

    def _start_capture(self) -> None:
        if self.capture.running:
            return
        device = self.iface_combo.currentData()
        if not device:
            QMessageBox.warning(self, "无法开始捕获",
                                "没有可用网卡。\n请先安装 Npcap（https://npcap.com），"
                                "并勾选“Install Npcap in WinPcap API-compatible Mode”。")
            return

        bpf = self.capture_filter.text().strip()
        if not self.capture.start(device, bpf, self.chk_promisc.isChecked()):
            return
        self.lbl_state.setText("● 捕获中")
        self.lbl_state.setStyleSheet(f"color:{theme.COLORS['ok']}")

    def _stop_capture(self) -> None:
        if self.capture.running:
            self.capture.stop()

    def _on_capture_started(self) -> None:
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.act_start.setEnabled(False)
        self.act_stop.setEnabled(True)
        iface = self.iface_combo.currentText()
        self.statusBar().showMessage(f"正在捕获：{iface}", 4000)

    def _on_capture_stopped(self) -> None:
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.act_start.setEnabled(True)
        self.act_stop.setEnabled(False)
        self.lbl_state.setText("● 已停止")
        self.lbl_state.setStyleSheet(f"color:{theme.COLORS['warn']}")
        self.statusBar().showMessage("捕获已停止", 4000)

    def _on_capture_error(self, message: str) -> None:
        self.lbl_state.setText("● 错误")
        self.lbl_state.setStyleSheet(f"color:{theme.COLORS['danger']}")
        QMessageBox.critical(self, "抓包错误", message)

    # ============================================================ 报文入表

    def _on_packets(self, records: list) -> None:
        resolver = self.resolver
        lookup = resolver.lookup
        for record in records:
            if record.sport is not None:
                record.pid, record.pname = lookup(
                    record.proto, record.src, record.dst, record.sport, record.dport
                )
            self.stats.feed(record)
            self.flows.feed_record(record)

        at_bottom = self._is_at_bottom()
        self.model.add_records(records)
        if self._follow_tail and at_bottom:
            self.table.scrollToBottom()

    def _is_at_bottom(self) -> bool:
        bar = self.table.verticalScrollBar()
        return bar.value() >= bar.maximum() - 4

    def _on_row_changed(self, current, previous) -> None:
        record = self.model.record_at(current.row()) if current.isValid() else None
        if record is None:
            self.tree.clear_record()
            self.hexview.set_data(b"")
            return
        self.tree.show_record(record)
        self.hexview.set_data(record.raw)

    # ============================================================ 过滤器

    def _validate_filter_ui(self) -> None:
        text = self.filter_edit.text().strip()
        error = validate(text) if text else None
        self.filter_edit.setProperty("invalid", bool(error))
        self.filter_edit.style().unpolish(self.filter_edit)
        self.filter_edit.style().polish(self.filter_edit)
        self.filter_edit.setToolTip(error or "显示过滤器语法：F1 查看帮助")

    def _apply_display_filter(self) -> None:
        text = self.filter_edit.text().strip()
        try:
            new_filter = DisplayFilter(text) if text else None
        except FilterSyntaxError as exc:
            self.filter_edit.setFocus()
            QMessageBox.warning(self, "过滤器语法错误", str(exc))
            return
        self._display_filter = new_filter
        self.model.set_filter(new_filter)
        self.tree.clear_record()
        self.hexview.set_data(b"")
        shown = self.model.visible_count()
        self.lbl_shown.setText(f"显示 {shown}")
        self.statusBar().showMessage(
            f"过滤器已应用：{text or '(清空)'}，命中 {shown} 条", 5000
        )
        if self._follow_tail:
            self.table.scrollToBottom()

    def _apply_preset(self, index: int) -> None:
        if index <= 0:
            return
        _, expression = PRESET_FILTERS[index]
        self.filter_edit.setText(expression)
        self._apply_display_filter()

    # ============================================================ 文件

    def _open_pcap(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "打开抓包文件", "", "pcap 文件 (*.pcap *.pcapng *.cap);;所有文件 (*.*)"
        )
        if not path:
            return
        if self.capture.running:
            self._stop_capture()

        self.progress = QProgressDialog("正在读取 pcap…", "取消", 0, 0, self)
        self.progress.setWindowTitle("打开文件")
        self.progress.setWindowModality(Qt.WindowModal)
        self.progress.setMinimumDuration(300)
        self.progress.show()

        self._load_worker = _LoadWorker(path, self)
        self._load_worker.finishedLoading.connect(self._on_pcap_loaded)
        self._load_worker.failed.connect(self._on_load_failed)
        self._load_worker.start()

    def _on_pcap_loaded(self, records: list, linktype: int) -> None:
        if hasattr(self, "progress"):
            self.progress.close()
        self._clear()
        self._on_packets(records)
        self.statusBar().showMessage(f"已加载 {len(records)} 条报文", 5000)

    def _on_load_failed(self, message: str) -> None:
        if hasattr(self, "progress"):
            self.progress.close()
        QMessageBox.critical(self, "读取失败", message)

    def load_path_sync(self, path: str) -> int:
        """同步加载 pcap（供命令行参数与自动化截图使用）。"""
        self._clear()
        records, _linktype = load_pcap(path)
        self._on_packets(records)
        self._tick()
        self.statusBar().showMessage(f"已加载 {len(records)} 条报文：{os.path.basename(path)}", 8000)
        return len(records)

    def _save_pcap(self) -> None:
        records = self.model.visible_records()
        if not records:
            QMessageBox.information(self, "没有可保存的数据", "当前列表为空。")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "保存抓包文件", "capture.pcap", "pcap 文件 (*.pcap)"
        )
        if not path:
            return
        try:
            count = save_pcap(path, records)
        except Exception as exc:
            QMessageBox.critical(self, "保存失败", str(exc))
            return
        self.statusBar().showMessage(f"已保存 {count} 条报文到 {os.path.basename(path)}", 5000)

    # ============================================================ 分析

    def _show_stats(self) -> None:
        if self.stats.total == 0:
            QMessageBox.information(self, "暂无数据", "还没有捕获到报文。")
            return
        StatisticsDialog(self.stats, self).exec()

    def _show_flows(self) -> None:
        streams = sorted(self.flows.tracker.streams(), key=lambda s: -s.packets)
        if not streams:
            QMessageBox.information(self, "暂无 TCP 流", "还没有捕获到 TCP 报文。")
            return
        FlowsDialog(streams, self).exec()

    def _show_current_flow(self) -> None:
        index = self.table.currentIndex()
        record = self.model.record_at(index.row()) if index.isValid() else None
        if record is None:
            return
        if record.flow_no is None:
            QMessageBox.information(self, "非 TCP 报文", "当前报文不属于任何 TCP 流。")
            return
        streams = sorted(self.flows.tracker.streams(), key=lambda s: -s.packets)
        dialog = FlowsDialog(streams, self)
        for row in range(dialog.table.rowCount()):
            item = dialog.table.item(row, 0)
            if item and item.text() == f"#{record.flow_no}":
                dialog.table.selectRow(row)
                break
        dialog.exec()

    def _clear(self) -> None:
        self.model.clear()
        self.stats.reset()
        self.flows.reset()
        self.tree.clear_record()
        self.hexview.set_data(b"")
        self.lbl_counts.setText("报文 0")
        self.lbl_shown.setText("显示 0")

    # ============================================================ 状态栏

    def _tick(self) -> None:
        stats = self.capture.stats()
        self.lbl_counts.setText(f"报文 {self.stats.total}")
        self.lbl_shown.setText(f"显示 {self.model.visible_count()}")
        if self.capture.running:
            self.lbl_rate.setText(f"{stats['rate']} 包/秒")
            self.lbl_drops.setText(f"丢弃 {stats['dropped']}")
        else:
            self.lbl_rate.setText("0 包/秒")
        if not self.capture.running and self.stats.total == 0:
            self.lbl_state.setText("● 空闲")
            self.lbl_state.setStyleSheet(f"color:{theme.COLORS['muted']}")

    # ============================================================ 生命周期

    def closeEvent(self, event) -> None:
        if self.capture.running:
            self.capture.stop()
        self.resolver.stop()
        if self._load_worker is not None and self._load_worker.isRunning():
            self._load_worker.wait(1500)
        super().closeEvent(event)
