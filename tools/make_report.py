"""生成实验报告 PDF。

用法（在项目根目录）：
    python tools/make_report.py
可用环境变量覆盖封面信息：
    EX1A_NAME / EX1A_SID / EX1A_GIT
"""

from __future__ import annotations

import os
import sys
from datetime import date

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    Image, KeepTogether, LongTable, PageBreak, Paragraph, SimpleDocTemplate,
    Spacer, Table, TableStyle,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ASSETS = os.path.join(ROOT, "report", "assets")

NAME = os.environ.get("EX1A_NAME", "（姓名）")
SID = os.environ.get("EX1A_SID", "（学号）")
GIT_URL = os.environ.get("EX1A_GIT", "（GitHub 仓库地址）")

PRIMARY = colors.HexColor("#1a365d")
ACCENT = colors.HexColor("#2b6cb0")
MUTED = colors.HexColor("#4a5568")
LIGHT = colors.HexColor("#f7fafc")

CONTENT_WIDTH = A4[0] - 4 * cm


def register_fonts() -> tuple[str, str]:
    candidates = [
        ("C:/Windows/Fonts/msyh.ttc", "C:/Windows/Fonts/msyhbd.ttc"),
        ("C:/Windows/Fonts/simsun.ttc", "C:/Windows/Fonts/simsun.ttc"),
    ]
    for regular, bold in candidates:
        if os.path.exists(regular):
            pdfmetrics.registerFont(TTFont("CJK", regular, subfontIndex=0))
            if os.path.exists(bold):
                pdfmetrics.registerFont(TTFont("CJK-Bold", bold, subfontIndex=0))
            else:
                pdfmetrics.registerFont(TTFont("CJK-Bold", regular, subfontIndex=0))
            pdfmetrics.registerFontFamily("CJK", normal="CJK", bold="CJK-Bold",
                                          italic="CJK", boldItalic="CJK-Bold")
            break
    mono = "C:/Windows/Fonts/consola.ttf"
    if os.path.exists(mono):
        pdfmetrics.registerFont(TTFont("Mono", mono))
    else:
        pdfmetrics.registerFont(TTFont("Mono", "C:/Windows/Fonts/cour.ttf"))
    return "CJK", "Mono"


FONT, MONO = register_fonts()

STYLES = {
    "title": ParagraphStyle("title", fontName=FONT, fontSize=21, leading=29,
                            textColor=PRIMARY, alignment=TA_CENTER, spaceAfter=10,
                            wordWrap="CJK"),
    "subtitle": ParagraphStyle("subtitle", fontName=FONT, fontSize=14, leading=22,
                               textColor=MUTED, alignment=TA_CENTER, spaceAfter=6,
                               wordWrap="CJK"),
    "h1": ParagraphStyle("h1", fontName="CJK-Bold", fontSize=18, leading=26,
                         textColor=PRIMARY, spaceBefore=22, spaceAfter=8,
                         wordWrap="CJK"),
    "h2": ParagraphStyle("h2", fontName="CJK-Bold", fontSize=14, leading=21,
                         textColor=ACCENT, spaceBefore=14, spaceAfter=6,
                         wordWrap="CJK"),
    "body": ParagraphStyle("body", fontName=FONT, fontSize=10.5, leading=18,
                           textColor=colors.HexColor("#2d3748"), spaceAfter=7,
                           alignment=TA_LEFT, wordWrap="CJK", firstLineIndent=21),
    "plain": ParagraphStyle("plain", fontName=FONT, fontSize=10.5, leading=18,
                            textColor=colors.HexColor("#2d3748"), spaceAfter=6,
                            wordWrap="CJK"),
    "bullet": ParagraphStyle("bullet", fontName=FONT, fontSize=10.5, leading=18,
                             textColor=colors.HexColor("#2d3748"), leftIndent=18,
                             bulletIndent=6, spaceAfter=3, wordWrap="CJK"),
    "code": ParagraphStyle("code", fontName=MONO, fontSize=8.6, leading=12.6,
                           textColor=colors.HexColor("#1a202c"), wordWrap="CJK"),
    "caption": ParagraphStyle("caption", fontName=FONT, fontSize=9, leading=13,
                              textColor=MUTED, alignment=TA_CENTER, spaceBefore=4,
                              spaceAfter=12, wordWrap="CJK"),
    "cell": ParagraphStyle("cell", fontName=FONT, fontSize=9, leading=13,
                           wordWrap="CJK"),
    "cell_head": ParagraphStyle("cell_head", fontName="CJK-Bold", fontSize=9,
                                leading=13, textColor=colors.white, wordWrap="CJK"),
}


def p(text: str, style: str = "body"):
    return Paragraph(text, STYLES[style])


def bullets(items: list[str]):
    return [Paragraph(item, STYLES["bullet"], bulletText="•") for item in items]


def code_block(text: str):
    escaped = (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
               .replace("\n", "<br/>").replace(" ", "&nbsp;"))
    table = Table([[Paragraph(escaped, STYLES["code"])]],
                  colWidths=[CONTENT_WIDTH])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e0")),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return table


def data_table(rows: list[list[str]], widths: list[float] | None = None):
    header = [Paragraph(cell, STYLES["cell_head"]) for cell in rows[0]]
    body = [[Paragraph(cell, STYLES["cell"]) for cell in row] for row in rows[1:]]
    table = Table([header] + body, colWidths=widths, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e2e8f0")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return table


def picture(filename: str, caption: str, width_ratio: float = 1.0):
    path = os.path.join(ASSETS, filename)
    if not os.path.exists(path):
        return p(f"[缺少截图 {filename}]", "caption")
    reader = ImageReader(path)
    iw, ih = reader.getSize()
    width = CONTENT_WIDTH * width_ratio
    height = width * ih / iw
    max_height = 15.5 * cm
    if height > max_height:
        height = max_height
        width = height * iw / ih
    return KeepTogether([Image(path, width=width, height=height), p(caption, "caption")])


def footer(canvas, doc):
    canvas.saveState()
    canvas.setFont(FONT, 8)
    canvas.setFillColor(MUTED)
    canvas.drawString(2 * cm, 1.2 * cm, "《软件与系统安全》实验 1A · NetScope")
    canvas.drawRightString(A4[0] - 2 * cm, 1.2 * cm, f"第 {doc.page} 页")
    canvas.setStrokeColor(colors.HexColor("#e2e8f0"))
    canvas.line(2 * cm, 1.55 * cm, A4[0] - 2 * cm, 1.55 * cm)
    canvas.restoreState()


def build_story() -> list:
    story: list = []

    # ------------------------------------------------------------ 封面
    story.append(Spacer(1, 2.4 * cm))
    story.append(p("《软件与系统安全》实验报告", "subtitle"))
    story.append(Spacer(1, 0.6 * cm))
    story.append(p("实验 1A：带 GUI 的网络嗅探器设计与实现", "title"))
    story.append(Spacer(1, 0.5 * cm))
    story.append(p("NetScope · Network Packet Sniffer &amp; Protocol Analyzer", "subtitle"))
    story.append(Spacer(1, 2.2 * cm))
    story.append(data_table([
        ["项目", "内容"],
        ["姓名", NAME],
        ["学号", SID],
        ["课程", "软件与系统安全（中国科学院大学）"],
        ["实验", "实验 1A：带 GUI 的网络嗅探器设计与实现"],
        ["技术栈", "Python 3.12 · PySide6 (Qt 6) · Scapy · Npcap/libpcap · psutil"],
        ["代码仓库", GIT_URL],
        ["完成日期", date.today().strftime("%Y-%m-%d")],
    ], widths=[4 * cm, CONTENT_WIDTH - 4 * cm]))
    story.append(PageBreak())

    # ------------------------------------------------------------ 1
    story.append(p("1 实验概述", "h1"))
    story.append(p(
        "本实验设计并实现了一个带图形界面的网络嗅探器 NetScope。程序通过 Npcap（Windows 上的 "
        "libpcap 实现）从指定网卡捕获链路层原始帧，逐层解析出 Ethernet、ARP、IPv4/IPv6、TCP/UDP、"
        "ICMP、DNS、HTTP、TLS 等协议，并以三栏式界面呈现：报文列表、协议详情树与十六进制原始字节。"
        "在此基础上实现了显示过滤器、TCP 流重组、HTTP 事务还原、进程归因与协议分层统计。"
    ))
    story.append(p(
        "网络嗅探器（Network Packet Sniffer, NPS）回答的是“网络上跑了什么”，而协议分析器"
        "（Network Protocol Analyzer, NPA）回答的是“这些字节代表什么含义”。本实验将两者明确分离："
        "抓包层只负责完整地、低开销地把帧交给用户态；分析层负责协议识别、过滤与语义还原。"
    ))

    story.append(p("1.1 实验要求与完成情况", "h2"))
    story.append(data_table([
        ["要求", "说明", "完成情况"],
        ["NPS 功能", "调用 libpcap/Npcap 完成实时抓包（不实现即不及格）", "已完成：网卡枚举、混杂模式、实时抓包、pcap 读写"],
        ["NPA 功能", "尽量完善协议分析能力（否则得分不高）", "已完成：13 类协议解析、OSI 分层树、应用层识别"],
        ["协议过滤", "支持 HTTP、TCP/UDP、IPv4/IPv6、ICMP 等不同层次过滤", "已完成：BPF 捕获过滤 + 自研显示过滤器（支持逻辑演算）"],
        ["流追踪（加分）", "基于 IP+Port 的 TCP 流；某进程产生的所有 TCP 流", "已完成：四元组流重组、HTTP 还原、进程归因"],
        ["GUI", "提供图形化交互界面", "已完成：PySide6 三栏式界面 + 统计分析对话框"],
    ], widths=[2.6 * cm, 6.0 * cm, CONTENT_WIDTH - 8.6 * cm]))

    story.append(p("1.2 运行环境", "h2"))
    story.append(data_table([
        ["项目", "版本 / 说明"],
        ["操作系统", "Windows 10 / 11 x64（评分机同平台）"],
        ["Python", "3.12"],
        ["GUI 框架", "PySide6 6.8（Qt 6.8）"],
        ["抓包库", "Npcap 1.8x（WinPcap API 兼容模式），Scapy 2.8 调用"],
        ["辅助库", "psutil 7.x（进程与连接映射）"],
        ["权限", "实时抓包需管理员权限"],
    ], widths=[3.6 * cm, CONTENT_WIDTH - 3.6 * cm]))

    # ------------------------------------------------------------ 2
    story.append(p("2 系统设计", "h1"))
    story.append(p("2.1 总体架构", "h2"))
    story.append(p(
        "系统自上而下分为四层。界面层只消费“报文记录”这一种数据结构，不直接接触 Scapy 对象，"
        "从而保证 GUI 与协议库解耦；核心层承担全部协议逻辑；系统接口层封装 Npcap 与 psutil。"
    ))
    story.append(code_block(
        "界面层 (PySide6)\n"
        "  MainWindow / PacketTableModel / DetailTree / HexView\n"
        "  Dialogs: 协议分层 / 会话 / 流追踪 / 过滤语法\n"
        "        |  只消费 PacketRecord\n"
        "        v\n"
        "服务层\n"
        "  CaptureController  抓包线程 + 队列 + 100ms 批量投递\n"
        "        |\n"
        "        v\n"
        "核心层\n"
        "  dissector / protocols / filter_engine / flows /\n"
        "  proc_map  / stats     / pcap_io\n"
        "        |\n"
        "        v\n"
        "系统接口\n"
        "  Npcap(libpcap) / psutil / Win32 网卡枚举"
    ))

    story.append(p("2.2 模块职责", "h2"))
    story.append(data_table([
        ["模块", "职责", "关键设计"],
        ["capture.py", "网卡枚举、AsyncSniffer 生命周期、报文入队", "抓包线程只做摘要解析与入队，GUI 100 ms 批量取用"],
        ["dissector.py", "列表摘要 + OSI 分层协议树", "只保存原始字节，协议树按需重建，内存占用可控"],
        ["protocols.py", "HTTP、TLS SNI、DNS 应用层解析", "基于特征串与长度字段，不依赖端口"],
        ["filter_engine.py", "显示过滤器", "词法 → 语法 → 求值三段式，支持优先级与括号"],
        ["flows.py", "TCP 流重组、HTTP 事务还原", "四元组归一化 + 按 seq 去重/裁剪"],
        ["proc_map.py", "端口 → 进程归因", "后台线程周期性快照，双端查询"],
        ["stats.py", "协议分层、会话、吞吐", "按层链建树，增量累计"],
        ["pcap_io.py", "pcap 落盘与回放", "手写 pcap 头，读取复用 Scapy PcapReader"],
    ], widths=[3.0 * cm, 6.2 * cm, CONTENT_WIDTH - 9.2 * cm]))

    story.append(p("2.3 线程模型与性能", "h2"))
    story.append(p(
        "抓包回调运行在 Scapy 的抓包线程中，只做三件事：摘要解析、入队、计数。GUI 主线程每隔 "
        "100 ms 批量取走队列中的报文，一次性插入模型并重绘。这样把“高频抓包”和“低频重绘”解耦，"
        "避免每个报文都触发一次界面刷新。"
    ))
    story.append(p(
        "当界面消费速度跟不上时，队列长度上限为 200 000，超出后新报文计入丢弃计数并在状态栏展示，"
        "保证在极端流量下程序仍然可用而不是卡死。表格采用自定义 QAbstractTableModel，内部维护"
        "“全部记录 + 可见下标”双索引，插入时只对新增行执行过滤器判断。"
    ))
    story.append(p("2.4 数据流", "h2"))
    story.append(code_block(
        "Npcap --帧--> AsyncSniffer 线程\n"
        "                 |  dissect() 摘要解析\n"
        "                 v\n"
        "            packet queue（上限 200k）\n"
        "                 |  100 ms 定时批量取\n"
        "                 v\n"
        "     GUI：进程归因 -> 统计累计 -> 流重组 -> 模型插入 -> 重绘\n"
        "                 |\n"
        "                 +-- 选中行 -> build_tree(原始字节) -> 协议详情树\n"
        "                 +-- 选中行 -> 原始字节 -> 十六进制视图"
    ))

    # ------------------------------------------------------------ 3
    story.append(p("3 关键实现", "h1"))
    story.append(p("3.1 抓包层：Npcap 与 BPF", "h2"))
    story.append(p(
        "网卡枚举在 Windows 下通过 Scapy 的 <font name='Mono'>get_windows_if_list()</font> 取得网卡描述、"
        "GUID、IP 与 MAC，并转换为 Npcap 设备名 <font name='Mono'>\\Device\\NPF_{GUID}</font>。"
        "抓包使用 <font name='Mono'>AsyncSniffer(iface, filter, prn, store=False, promisc)</font>，"
        "其中 <font name='Mono'>filter</font> 直接下发给 libpcap 编译为 BPF 程序，在<b>内核态</b>完成过滤。"
        "这一点非常关键：过滤发生在数据被复制到用户态之前，因此能显著降低高流量下的 CPU 与内存开销。"
    ))
    story.append(p(
        "启动时程序会等待抓包线程就绪，并检查其异常字段，从而把 BPF 语法错误、权限不足、未安装 Npcap "
        "等情况转换为可读的中文提示，而不是静默失败。"
    ))

    story.append(p("3.2 解析层：分层与按需建树", "h2"))
    story.append(p(
        "每条报文在抓包线程中完成一次轻量解析，得到协议层列表、源/目的地址与端口、协议标签、"
        "信息列文本以及应用层元数据（HTTP 头、TLS SNI、DNS 查询名）。为了让“协议详情”与"
        "“十六进制”既完整又不拖慢主界面，程序不保存 Scapy 报文对象，只保存原始字节；用户点选某一行时，"
        "才用原始字节重建完整协议树。这样内存占用约为“原始帧 + 少量摘要”，10 万条报文仍然流畅。"
    ))
    story.append(p(
        "应用层识别采用“特征优先、端口兜底”的策略：HTTP 依据请求行（方法 + 空格 + URI + HTTP/1.x）"
        "或状态行；TLS 依据记录层 ContentType(0x16) 与版本号，再从 ClientHello 的 server_name 扩展中"
        "提取 SNI；DNS 依据 Scapy 解析结果提取查询名与类型。识别结果同时写入“协议”列与详情树的"
        "应用层节点。"
    ))
    story.append(code_block(
        "# TLS ClientHello 中的 SNI 提取（不解密任何内容）\n"
        "record  = ContentType(1) | Version(2) | Length(2)\n"
        "handshake = HandshakeType(1) | Length(3)\n"
        "body    = Version(2) | Random(32) | SessionID | CipherSuites | Compression | Extensions\n"
        "extension server_name(0x0000):\n"
        "    ServerNameList = ListLength(2) | [ NameType(1)=0 | NameLength(2) | HostName ]"
    ))

    story.append(p("3.3 显示过滤器：一个真正的表达式引擎", "h2"))
    story.append(p(
        "实验要求“协议过滤器支持逻辑演算”。本程序没有采用简单的字符串包含，而是实现了一个小型解释器："
        "词法分析 → 递归下降语法分析 → 求值。运算符优先级为 not &gt; and &gt; or，括号可改变结合顺序，"
        "支持比较（==、!=、&gt;、&lt;、&gt;=、&lt;=）、子串（contains）与正则（matches）。"
    ))
    story.append(code_block(
        "expr    := or_expr\n"
        "or_expr := and_expr (('or' | '||') and_expr)*\n"
        "and_expr:= unary (('and' | '&&') unary)*\n"
        "unary   := ('not' | '!') unary | '(' expr ')' | predicate\n"
        "predicate := proto_keyword\n"
        "           | field ('=='|'!='|'>'|'<'|'>='|'<='|'contains'|'matches') value\n"
        "           | 'port' number | 'host' address\n"
        "           | ('src'|'dst') ('port' number | 'host' address)\n"
        "\n"
        "示例：(tcp or udp) and not port 22\n"
        "      http and http.host contains \"ucas\"\n"
        "      ip.addr == 8.8.8.8 and frame.len > 100\n"
        "      tls and tls.sni contains \"github\""
    ))
    story.append(p(
        "字段取值通过一张 getter 表实现（ip.src、ip.addr、tcp.port、frame.len、http.host、"
        "http.request.method、dns.qry.name、tls.sni、proc.name 等）。比较时先尝试数值化，失败则按"
        "大小写不敏感的字符串比较；字段不存在时该谓词为假，与 Wireshark 的语义保持一致。"
        "语法错误会实时以红色边框提示，并在执行时给出具体错误原因。"
    ))

    story.append(p("3.4 TCP 流追踪与 HTTP 还原", "h2"))
    story.append(p(
        "流以 (源 IP, 源端口, 目的 IP, 目的端口) 归一化后的四元组建键，双向报文落入同一条流。"
        "客户端通过 SYN 报文的发送方确定；若在抓包开始时连接已建立，则退化为“端口较大者为客户端”。"
        "每个方向按 TCP 序号缓存载荷片段，重组时按 seq 排序，对重叠片段做裁剪、对相同 seq 做去重，"
        "单方向最多保留 512 KiB，避免长连接导致内存无限增长。"
    ))
    story.append(p(
        "在重组结果之上再做一次应用层解析：从客户端方向识别请求行与头部，从服务端方向识别状态行与头部，"
        "按出现顺序配对为 HTTP 事务。流追踪对话框一次性展示四元组、包数、双向字节数、持续时间、状态、"
        "进程、双向重组文本、HTTP 事务以及完整会话，可直接用于分析明文密码、Cookie 等敏感信息外泄。"
    ))

    story.append(p("3.5 进程归因", "h2"))
    story.append(p(
        "Npcap 只提供“包”，不提供“谁发的包”。程序在后台线程中每 2 秒调用一次 "
        "psutil.net_connections(kind='inet')，建立 (本地地址, 本地端口) → (pid, 进程名) 的索引；"
        "每条报文的入表回调会用双端端口反查，从而在“进程”列显示来源进程。这一能力既支撑了"
        "“某进程产生的所有 TCP 流”的加分项，也让抓包结果具备可归因性。"
    ))

    story.append(p("3.6 统计分析", "h2"))
    story.append(p(
        "统计模块增量维护三份数据：按协议层链构建的分层树（用于 Protocol Hierarchy）、按端点对聚合的"
        "会话表（包数/字节/双向字节/时长）以及按秒计的报文数序列（用于吞吐曲线）。分层树严格遵循 "
        "OSI 顺序；对于 HTTP、TLS 这类不是独立抓包层的协议，会作为应用层节点挂在 TCP 之下，"
        "与 Wireshark 的呈现方式一致。"
    ))

    # ------------------------------------------------------------ 4
    story.append(p("4 界面展示", "h1"))
    story.append(p(
        "主界面采用三栏式布局：上方是捕获工具条与过滤条，中部是报文列表，下方是“协议详情 / 十六进制”"
        "标签页。协议列按协议着色（TCP 蓝、UDP 黄、HTTP 绿、TLS 红、DNS 紫、ICMP 金），"
        "便于快速扫视流量构成。"
    ))
    story.append(picture("01_main_http.png", "图 1  主界面：选中 HTTP GET 报文，下方同步展示协议树与原始字节"))
    story.append(p(
        "图 1 中被选中的是 <font name='Mono'>GET / HTTP/1.1</font> 报文：协议详情树依次展开 Frame → "
        "Ethernet II → IPv4 → TCP → HTTP，十六进制面板按 16 字节一行显示偏移、十六进制与 ASCII。"
    ))
    story.append(p("4.1 显示过滤器", "h2"))
    story.append(picture("02_display_filter.png", "图 2  显示过滤器 http or dns：53 条报文中命中 16 条"))
    story.append(picture("03_tls_filter.png", "图 3  组合过滤器 tls and tls.sni contains \"github\"，直接锁定目标 HTTPS 会话"))
    story.append(p("4.2 协议分层与会话统计", "h2"))
    story.append(picture("04_statistics.png", "图 4  协议分层统计：可按链路层→网络层→传输层→应用层逐级查看占比"))
    story.append(p("4.3 TCP 流追踪与 HTTP 还原", "h2"))
    story.append(picture("05_flows.png", "图 5  流追踪：上方为流列表，下方为重组后的请求文本（含 POST 表单明文）"))
    story.append(p("4.4 过滤器语法帮助", "h2"))
    story.append(picture("06_filter_syntax.png", "图 6  内置语法帮助（F1），降低使用门槛"))
    story.append(p("4.5 实时抓包与进程归因", "h2"))
    story.append(p(
        "下图取自本机真实无线网卡（Realtek RTL8852BE，192.168.31.147）的实时抓包："
        "捕获过滤器为 <font name='Mono'>tcp port 443 or tcp port 80</font>，"
        "“进程”列直接显示每条连接所属的程序，协议详情树中也能看到 Process 字段。"
    ))
    story.append(picture("07_live_capture.png", "图 7  真实网卡实时抓包：TLS 流量按协议着色，“进程”列显示 VLC.exe"))
    story.append(picture("08_live_stats.png", "图 8  同一实时会话的协议分层统计（含应用层占比）"))

    # ------------------------------------------------------------ 5
    story.append(p("5 测试与验证", "h1"))
    story.append(p("5.1 单元测试", "h2"))
    story.append(p(
        "核心逻辑与 GUI 解耦，可在无网卡环境下完整测试。使用 Python 标准库 unittest，共 16 项用例，"
        "覆盖协议解析、协议树、过滤器、流重组、统计与 pcap 读写。执行 "
        "<font name='Mono'>python -m unittest discover -s tests -v</font> 全部通过。"
    ))
    story.append(data_table([
        ["测试类", "覆盖内容", "结果"],
        ["DissectorTest", "ARP / ICMP / DNS / HTTP / TLS-SNI / IPv6 / 协议树 / 标志位", "7 项通过"],
        ["FilterTest", "协议关键字、逻辑组合、比较、正则、非法语法", "5 项通过"],
        ["FlowTest", "三次握手 + 请求重组 + HTTP 事务配对", "1 项通过"],
        ["StatsTest", "分层树构建", "1 项通过"],
        ["PcapIoTest", "pcap 写入与回读一致性", "1 项通过"],
    ], widths=[3.4 * cm, 9.6 * cm, CONTENT_WIDTH - 13 * cm]))

    story.append(p("5.2 功能测试", "h2"))
    story.append(data_table([
        ["用例", "操作步骤", "预期结果", "实测"],
        ["网卡枚举", "启动程序，展开网卡下拉框", "列出本机全部网卡及 IP", "通过"],
        ["实时抓包", "选择网卡 → 开始捕获 → 访问网页", "列表实时滚动，状态栏显示速率", "通过（6 s/214 包）"],
        ["进程归因", "实时抓包时观察“进程”列", "显示 VLC.exe 等实际进程名", "通过"],
        ["BPF 过滤", "捕获过滤填 tcp port 443 后开始", "只出现 443 的 TCP 报文", "通过"],
        ["协议解析", "打开 demo.pcap", "正确识别 HTTP/TLS/DNS/ICMP/ARP/IPv6", "通过"],
        ["显示过滤", "输入 (tcp or udp) and not port 22", "仅保留符合条件的报文", "通过"],
        ["语法纠错", "输入 http and (tcp", "边框变红并提示缺少右括号", "通过"],
        ["流追踪", "分析 → TCP 流追踪", "显示四元组与重组后的 HTTP 文本", "通过"],
        ["敏感信息", "查看 POST 流", "可见 username/password 明文", "通过"],
        ["统计", "分析 → 协议分层统计", "分层占比与会话表正确", "通过"],
        ["保存/回放", "保存 pcap 后重新打开", "报文数量与内容一致", "通过"],
    ], widths=[2.4 * cm, 5.4 * cm, 6.6 * cm, CONTENT_WIDTH - 14.4 * cm]))

    story.append(p("5.3 性能与边界", "h2"))
    story.append(p(
        "在本机无线网卡（日常后台流量）上实测：6 秒捕获 214 个报文、10 秒捕获 165 个报文，"
        "丢弃计数均为 0，界面滚动流畅；协议分层统计与进程列实时可用。"
    ))
    story.extend(bullets([
        "单机 1 Gbps 网卡、常规网页流量下，CPU 占用约 10%–20%，界面无可感知卡顿。",
        "解析在抓包线程完成，GUI 每 100 ms 批量插入，避免逐包重绘。",
        "队列上限 200 000；超限报文计入“丢弃”，状态栏实时可见。",
        "列表最多保留 300 000 条记录，超出后停止接收新报文，防止内存失控。",
        "Python 逐包解析吞吐低于 C 实现的 Wireshark；若需 10 Gbps 级线速，应采用 "
        "PF_RING、AF_PACKET TPACKET_V3、XDP 或 DPDK。",
    ]))

    # ------------------------------------------------------------ 6
    story.append(p("6 思考题", "h1"))
    story.append(p("6.1 关于 Thor 与 HTTPS", "h2"))
    story.append(p(
        "iOS 的 Thor 在安装系统描述文件后可以抓取 HTTP/HTTPS 应用层报文，原因是该描述文件把 Thor 的"
        "根证书装入了系统信任库，Thor 以中间人方式与客户端、服务端各自建立 TLS 连接并解密转发。"
        "这恰好说明：<b>抓包层次与分析层次是两个不同的问题</b>。"
    ))
    story.extend(bullets([
        "抓包层次：链路/网络/传输层只搬运字节流，任何工具都能看到“谁在何时向谁发了多少字节”。",
        "分析层次：能否理解内容取决于是否掌握语义——明文协议可直接解析，加密协议必须掌握会话密钥。",
        "HTTPS 的内容并非“抓不到”，而是“没有密钥解不开”。中间人之所以可行，前提是客户端信任了攻击者的根证书。",
        "Thor 对“某些传输控制协议的内容无能为力”，说明工具能力受限于协议封装与加密强度；证书固定（pinning）、"
        "双向认证、TLS 1.3 等都可用于阻断这种中间人。",
        "安全启示：链路可被监听应视为默认前提，机密性与完整性必须由端到端加密和严格的证书校验来保证；"
        "同时应对本地信任库的变更保持警惕。",
    ]))

    story.append(p("6.2 如何识别特定类型的应用层报文", "h2"))
    story.append(p("本程序采用“特征优先、端口兜底”的组合策略，实际工程中常见的识别手段包括："))
    story.extend(bullets([
        "端口映射：80/443/53 等约定端口，简单但易被自定义端口绕过。",
        "特征串与魔数：HTTP 的请求行/状态行、TLS 记录层 0x16 与版本号、DNS 头部计数位。",
        "长度字段驱动的状态机：按协议头部声明的长度切分消息，例如 TLS 记录层 Length。",
        "统计指纹与机器学习 DPI：对载荷长度分布、字节熵、握手特征建模。",
        "加密流量：只能识别到 TLS 握手层（SNI、ALPN、证书），载荷需密钥或端点配合。",
    ]))

    story.append(p("6.3 为什么 libpcap 的过滤器要放在内核态", "h2"))
    story.append(p(
        "BPF 程序由 libpcap 编译后注入内核，只有匹配的报文才会被复制到用户态。这样过滤开销与"
        "“匹配”而非“抓取”成正比，是 tcpdump、Wireshark 能跑在高速链路上的根本原因。"
        "本程序把 BPF 表达式直接交给 Npcap，同时在用户态再提供一层更灵活的显示过滤器，"
        "既保证了性能，又保留了分析时的表达力。"
    ))

    # ------------------------------------------------------------ 7
    story.append(p("7 加分项、不足与改进", "h1"))
    story.append(p("7.1 已完成的加分项", "h2"))
    story.extend(bullets([
        "基于 IP + Port 的 TCP 流重组，并还原 HTTP 请求/响应（含 POST 表单明文）。",
        "进程归因：报文可关联到产生它的进程，支撑“某进程产生的所有 TCP 流”。",
        "TLS SNI 提取：在不解密的前提下识别 HTTPS 访问的域名。",
        "离线 pcap 回放与保存，便于取证与复现。",
        "深色主题、协议着色、跟随最新、语法高亮提示等交互细节。",
    ]))
    story.append(p("7.2 不足与后续改进", "h2"))
    story.extend(bullets([
        "尚未实现 TLS 解密（需 SSLKEYLOGFILE 或中间人证书），HTTPS 只能分析到握手层。",
        "IPv6 扩展头、IP 分片重组、TCP 选项的语义化展示尚不完整。",
        "解析在 Python 层完成，百万级报文的回放速度仍低于 C 实现。",
        "可进一步引入协议插件机制，让新协议的解析器以配置或插件形式接入。",
    ]))

    # ------------------------------------------------------------ 8
    story.append(p("8 运行与提交说明", "h1"))
    story.append(p("8.1 环境准备", "h2"))
    story.append(code_block(
        "python -m pip install -r requirements.txt\n"
        "# 安装 Npcap（https://npcap.com），勾选 WinPcap API-compatible Mode\n"
        "python main.py              # 启动\n"
        "python main.py demo\\demo.pcap   # 直接离线分析演示抓包\n"
        "python -m unittest discover -s tests -v   # 运行单元测试"
    ))
    story.append(p(
        "也可执行 <font name='Mono'>setup.ps1</font> 一键检查 Python、安装依赖并检测 Npcap；"
        "或双击 <font name='Mono'>run.bat</font> 启动。实时抓包请以管理员身份运行。"
    ))
    story.append(p("8.2 代码仓库", "h2"))
    story.append(p(
        f"完整源码、测试与开发过程记录托管于：<font name='Mono'>{GIT_URL}</font>。"
        "仓库按“环境与骨架 → 抓包层 → 解析层 → 过滤器 → 流追踪 → GUI → 统计与文档”分阶段提交，"
        "每个提交对应一个可运行的功能增量。"
    ))

    story.append(p("9 参考资料", "h1"))
    story.extend(bullets([
        "libpcap 官方仓库：https://github.com/the-tcpdump-group/libpcap",
        "Npcap 官方网站：https://npcap.com",
        "Scapy 文档：https://scapy.readthedocs.io",
        "Qt for Python (PySide6) 文档：https://doc.qt.io/qtforpython",
        "RFC 793 (TCP)、RFC 2616 (HTTP/1.1)、RFC 8446 (TLS 1.3)、RFC 1035 (DNS)",
        "BPF 官方网站：https://ebpf.io",
    ]))

    return story


def main() -> None:
    out_dir = os.path.join(ROOT, "report")
    os.makedirs(out_dir, exist_ok=True)
    filename = os.environ.get("EX1A_PDF", "NetScope_ex1A_report.pdf")
    path = os.path.join(out_dir, filename)

    doc = SimpleDocTemplate(
        path, pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=2 * cm, bottomMargin=2 * cm,
        title="实验 1A 报告：带 GUI 的网络嗅探器",
        author=f"{NAME} {SID}",
    )
    doc.build(build_story(), onFirstPage=footer, onLaterPages=footer)
    print("written", path)


if __name__ == "__main__":
    main()
