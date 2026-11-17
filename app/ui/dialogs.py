"""各类分析对话框：协议分层统计、会话、TCP 流追踪、过滤器语法、关于。"""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import (
    QAbstractItemView, QDialog, QDialogButtonBox, QHBoxLayout, QHeaderView,
    QLabel, QPushButton, QSplitter, QTabWidget, QTableWidget, QTableWidgetItem,
    QTextBrowser, QTextEdit, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

from ..core.flows import TcpStream
from ..core.models import TreeNode
from ..core.stats import StatsCollector, endpoint_text
from . import theme


def _mono(point: int = 9) -> QFont:
    font = QFont("Cascadia Mono")
    font.setStyleHint(QFont.Monospace)
    font.setPointSize(point)
    return font


class IoChart(QWidget):
    """每秒报文数折线图（自绘，避免额外依赖）。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._seconds: list[int] = []
        self._counts: list[int] = []
        self.setMinimumHeight(180)

    def set_series(self, seconds: list[int], counts: list[int]) -> None:
        self._seconds, self._counts = seconds, counts
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect = self.rect().adjusted(56, 18, -18, -30)
        painter.fillRect(self.rect(), QColor(theme.COLORS["bg"]))

        if not self._counts:
            painter.setPen(QColor(theme.COLORS["muted"]))
            painter.drawText(self.rect(), Qt.AlignCenter, "暂无数据")
            painter.end()
            return

        peak = max(self._counts) or 1
        painter.setPen(QPen(QColor(theme.COLORS["border"]), 1))
        for i in range(5):
            y = rect.bottom() - rect.height() * i / 4
            painter.drawLine(rect.left(), int(y), rect.right(), int(y))
            painter.setPen(QColor(theme.COLORS["muted"]))
            painter.drawText(6, int(y) + 4, f"{int(peak * i / 4)}")
            painter.setPen(QPen(QColor(theme.COLORS["border"]), 1))

        count = len(self._counts)
        step = rect.width() / max(1, count - 1) if count > 1 else rect.width()
        points = []
        for i, value in enumerate(self._counts):
            x = rect.left() + i * step
            y = rect.bottom() - rect.height() * value / peak
            points.append((x, y))

        painter.setPen(QPen(QColor(theme.COLORS["accent"]), 2))
        for i in range(len(points) - 1):
            painter.drawLine(int(points[i][0]), int(points[i][1]),
                             int(points[i + 1][0]), int(points[i + 1][1]))

        painter.setBrush(QColor(theme.COLORS["accent"]))
        for x, y in points:
            painter.drawEllipse(int(x) - 2, int(y) - 2, 4, 4)

        painter.setPen(QColor(theme.COLORS["muted"]))
        painter.drawText(rect.left(), rect.bottom() + 20, "时间（秒）")
        painter.drawText(rect.right() - 90, rect.bottom() + 20, f"峰值 {peak} 包/秒")
        painter.end()


class StatisticsDialog(QDialog):
    def __init__(self, stats: StatsCollector, parent=None):
        super().__init__(parent)
        self.setWindowTitle("协议分层统计 / 会话")
        self.resize(980, 620)
        self._stats = stats

        layout = QVBoxLayout(self)
        summary = QLabel(
            f"总计 {stats.total} 个报文，{stats.total_bytes:,} 字节"
        )
        summary.setObjectName("Hint")
        layout.addWidget(summary)

        tabs = QTabWidget()
        layout.addWidget(tabs, 1)

        self.tree = QTreeWidget()
        self.tree.setColumnCount(2)
        self.tree.setHeaderLabels(["协议层级", "包数 / 占比"])
        self.tree.setUniformRowHeights(True)
        self.tree.header().setStretchLastSection(True)
        self.tree.setColumnWidth(0, 420)
        tabs.addTab(self.tree, "协议分层 (Protocol Hierarchy)")
        self._fill_tree(stats.hierarchy())

        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            ["协议", "端点 A", "端点 B", "包数", "字节", "A→B 字节", "时长(s)"]
        )
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        tabs.addTab(self.table, "会话 (Conversations)")
        self._fill_conversations(stats.conversations())

        self.chart = IoChart()
        tabs.addTab(self.chart, "吞吐 (IO Graph)")
        seconds, counts = stats.io_series()
        self.chart.set_series(seconds, counts)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        buttons.button(QDialogButtonBox.Close).setText("关闭")
        layout.addWidget(buttons)

    def _fill_tree(self, root: TreeNode) -> None:
        def add(parent, node: TreeNode, depth: int):
            item = QTreeWidgetItem([node.label, node.value])
            item.setFont(0, _mono())
            item.setFont(1, _mono())
            if depth == 0:
                item.setForeground(0, QColor(theme.COLORS["accent"]))
            parent.addChild(item)
            for child in node.children:
                add(item, child, depth + 1)
            return item

        item = QTreeWidgetItem([root.label, root.value])
        item.setFont(0, _mono())
        item.setForeground(0, QColor(theme.COLORS["accent"]))
        self.tree.addTopLevelItem(item)
        for child in root.children:
            add(item, child, 1)
        self.tree.expandAll()

    def _fill_conversations(self, rows: list[dict]) -> None:
        self.table.setRowCount(len(rows))
        for r, conv in enumerate(rows):
            values = [
                conv["protocol"],
                endpoint_text(conv["a"]),
                endpoint_text(conv["b"]),
                str(conv["packets"]),
                f"{conv['bytes']:,}",
                f"{conv['a_bytes']:,}",
                f"{conv['end'] - conv['start']:.3f}",
            ]
            for c, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setFont(_mono())
                if c == 0:
                    item.setForeground(theme.color_for(value))
                if c >= 3:
                    item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                self.table.setItem(r, c, item)


class FlowsDialog(QDialog):
    """TCP 流追踪：四元组、重组字节流、HTTP 事务。"""

    def __init__(self, streams: list[TcpStream], parent=None):
        super().__init__(parent)
        self.setWindowTitle("TCP 流追踪 (Flow Tracking)")
        self.resize(1100, 700)
        self._streams = streams

        layout = QVBoxLayout(self)
        self.hint = QLabel("基于 IP + Port 四元组的 TCP 流重组，可还原 HTTP 请求/响应")
        self.hint.setObjectName("Hint")
        layout.addWidget(self.hint)

        splitter = QSplitter(Qt.Vertical)
        layout.addWidget(splitter, 1)

        self.table = QTableWidget(0, 10)
        self.table.setHorizontalHeaderLabels(
            ["流号", "客户端", "服务端", "包数", "上行字节", "下行字节", "时长(s)", "状态", "进程", "协议"]
        )
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.itemSelectionChanged.connect(self._on_select)
        splitter.addWidget(self.table)

        self.detail_tabs = QTabWidget()
        self.c2s = QTextEdit()
        self.s2c = QTextEdit()
        self.http = QTextBrowser()
        self.raw = QTextEdit()
        for widget in (self.c2s, self.s2c, self.http, self.raw):
            widget.setFont(_mono())
            widget.setReadOnly(True)
        self.detail_tabs.addTab(self.c2s, "客户端 → 服务器")
        self.detail_tabs.addTab(self.s2c, "服务器 → 客户端")
        self.detail_tabs.addTab(self.http, "HTTP 事务")
        self.detail_tabs.addTab(self.raw, "完整会话")
        splitter.addWidget(self.detail_tabs)
        splitter.setSizes([340, 340])

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        buttons.button(QDialogButtonBox.Close).setText("关闭")
        layout.addWidget(buttons)

        self._fill()

    def _fill(self) -> None:
        widths = [58, 178, 178, 62, 88, 88, 74, 104, 110]
        for column, width in enumerate(widths):
            self.table.setColumnWidth(column, width)
        self.table.setRowCount(len(self._streams))
        for r, stream in enumerate(self._streams):
            service = ""
            for port in (stream.server[1], stream.client[1]):
                if port in (80, 8080, 8000):
                    service = "HTTP"
                    break
                if port in (443, 8443):
                    service = "TLS"
                    break
            values = [
                f"#{r}",
                f"{stream.client[0]}:{stream.client[1]}",
                f"{stream.server[0]}:{stream.server[1]}",
                str(stream.packets),
                f"{stream.bytes_c2s:,}",
                f"{stream.bytes_s2c:,}",
                f"{stream.duration:.3f}",
                stream.state,
                stream.pname or "-",
                service or "TCP",
            ]
            for c, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setFont(_mono())
                if c >= 3:
                    item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                self.table.setItem(r, c, item)
        if self._streams:
            self.table.selectRow(0)

    def _on_select(self) -> None:
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
        index = rows[0].row()
        if not (0 <= index < len(self._streams)):
            return
        stream = self._streams[index]
        self.c2s.setPlainText(stream.client_text() or "（该方向没有可重组的载荷）")
        self.s2c.setPlainText(stream.server_text() or "（该方向没有可重组的载荷）")
        self.http.setHtml(self._http_html(stream))
        self.raw.setPlainText(
            f"{stream.key_text}\n状态: {stream.state}  时长: {stream.duration:.3f}s "
            f"包数: {stream.packets}\n\n" + (stream.client_text() or "") + "\n" +
            (stream.server_text() or "")
        )

    @staticmethod
    def _http_html(stream: TcpStream) -> str:
        transactions = stream.http_transactions()
        if not transactions:
            return "<p style='color:#8b9199'>该流未识别出 HTTP 事务</p>"
        parts = ["<div style='font-family:Consolas,monospace;font-size:12px'>"]
        for i, trans in enumerate(transactions, 1):
            parts.append(f"<h3 style='color:#59c98a'>事务 {i}</h3>")
            req, resp = trans.get("request"), trans.get("response")
            if req:
                parts.append(
                    f"<p><b>{req.get('method')}</b> {req.get('uri')} "
                    f"<span style='color:#8b9199'>HTTP/{req.get('version')}</span></p><ul>"
                )
                for name, value in req.get("headers", []):
                    parts.append(f"<li>{name}: {value}</li>")
                parts.append("</ul>")
            if resp:
                parts.append(
                    f"<p><b style='color:#f7c948'>HTTP/{resp.get('version')} "
                    f"{resp.get('status')} {resp.get('reason')}</b></p><ul>"
                )
                for name, value in resp.get("headers", []):
                    parts.append(f"<li>{name}: {value}</li>")
                parts.append("</ul>")
        parts.append("</div>")
        return "".join(parts)


class FilterSyntaxDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("显示过滤器语法")
        self.resize(760, 620)
        layout = QVBoxLayout(self)
        browser = QTextBrowser()
        browser.setHtml(
            """
            <style>
              body { color:#d8dbe0; font-family:'Microsoft YaHei UI',sans-serif; font-size:13px; }
              code { color:#8ecdd6; font-family:Consolas,monospace; }
              h3 { color:#3f8cff; }
              td { padding:3px 10px; }
            </style>
            <h3>显示过滤器（Display Filter）</h3>
            <p>这是一个带优先级与括号的布尔表达式求值器：<code>not</code> &gt;
            <code>and</code> &gt; <code>or</code>，与 Wireshark 的过滤思想一致，
            但完全由本程序自行实现（词法 → 语法 → 求值）。</p>

            <h3>协议关键字</h3>
            <p><code>tcp</code> <code>udp</code> <code>icmp</code> <code>icmpv6</code>
            <code>arp</code> <code>ip</code> <code>ipv6</code> <code>dns</code>
            <code>http</code> <code>tls</code> <code>dhcp</code> <code>ssh</code></p>

            <h3>字段与运算符</h3>
            <table>
              <tr><td><code>ip.src == 10.0.0.5</code></td><td>源地址</td></tr>
              <tr><td><code>ip.addr == 8.8.8.8</code></td><td>任一方向地址</td></tr>
              <tr><td><code>tcp.port == 443</code></td><td>传输层端口</td></tr>
              <tr><td><code>port 80</code> / <code>host 192.168.1.1</code></td><td>简化写法</td></tr>
              <tr><td><code>src port 53</code></td><td>源端口</td></tr>
              <tr><td><code>frame.len &gt; 100</code></td><td>长度比较</td></tr>
              <tr><td><code>http.host contains "test"</code></td><td>子串匹配</td></tr>
              <tr><td><code>http.request.uri matches "\\\\.php"</code></td><td>正则匹配</td></tr>
              <tr><td><code>http.request.method == "POST"</code></td><td>HTTP 方法</td></tr>
              <tr><td><code>http.response.code == 404</code></td><td>状态码</td></tr>
              <tr><td><code>dns.qry.name contains "baidu"</code></td><td>DNS 查询名</td></tr>
              <tr><td><code>tls.sni contains "github"</code></td><td>HTTPS SNI（不解密）</td></tr>
              <tr><td><code>proc.name == "chrome.exe"</code></td><td>按进程过滤</td></tr>
            </table>

            <h3>组合示例</h3>
            <p><code>(tcp or udp) and not port 22</code></p>
            <p><code>http and http.host contains "ucas"</code></p>
            <p><code>ip.addr == 192.168.1.10 and frame.len &gt; 60</code></p>

            <h3>捕获过滤器（BPF）</h3>
            <p>捕获前过滤由 Npcap/libpcap 在内核态完成，语法遵循 pcap-filter，例如：
            <code>tcp port 80</code>、<code>udp and port 53</code>、
            <code>host 192.168.1.1</code>、<code>icmp</code>。</p>
            """
        )
        layout.addWidget(browser, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        buttons.button(QDialogButtonBox.Close).setText("关闭")
        layout.addWidget(buttons)


class AboutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("关于 NetScope")
        self.resize(560, 420)
        layout = QVBoxLayout(self)
        text = QLabel(
            """<h2 style='color:#3f8cff'>NetScope · 网络嗅探与协议分析器</h2>
            <p>《软件与系统安全》实验 1A：带 GUI 的网络嗅探器设计与实现</p>
            <p style='color:#8b9199'>NPS（Network Packet Sniffer）+ NPA（Network Protocol
            Analyzer）</p>
            <hr/>
            <p><b>抓包</b>：Npcap / libpcap（通过 Scapy AsyncSniffer 调用，支持 BPF 内核过滤）<br/>
            <b>解析</b>：Ethernet / VLAN / ARP / IPv4 / IPv6 / TCP / UDP / ICMP / DNS /
            HTTP / TLS(SNI) / DHCP<br/>
            <b>界面</b>：PySide6（Qt 6）<br/>
            <b>分析</b>：显示过滤器逻辑引擎、TCP 流重组、HTTP 还原、进程归因、协议分层统计</p>
            <p style='color:#8b9199'>仅用于授权网络环境下的教学与研究。</p>"""
        )
        text.setWordWrap(True)
        text.setTextFormat(Qt.RichText)
        layout.addWidget(text, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok)
        buttons.accepted.connect(self.accept)
        buttons.button(QDialogButtonBox.Ok).setText("确定")
        layout.addWidget(buttons)
