# NetScope · 带 GUI 的网络嗅探器

《软件与系统安全》实验 1A：**带 GUI 的网络嗅探器设计与实现**

NetScope 是一个运行在 Windows 上的桌面抓包与分析工具。抓包层通过 Scapy 调用
**Npcap / libpcap**，分析层自行实现协议树、显示过滤器、TCP 流重组与进程归因，
界面基于 **PySide6 (Qt 6)**。

> 仓库地址：https://github.com/c11220/NetScope-EX1A
> 课程：中国科学院大学《软件与系统安全》实验 1A

## 功能

| 层次 | 能力 |
| --- | --- |
| 抓包 (NPS) | 网卡枚举、混杂模式、BPF 内核过滤、实时速率/丢弃统计、pcap 读写 |
| 解析 (NPA) | Ethernet / VLAN / ARP / IPv4 / IPv6 / TCP / UDP / ICMP / ICMPv6 / DNS / DHCP / HTTP / TLS(SNI) |
| 过滤 | 自研显示过滤器（`and`/`or`/`not`、括号、`==`/`!=`/`>`/`<`、`contains`、`matches`） |
| 分析 | 协议分层统计、会话统计、吞吐曲线、TCP 流重组、HTTP 请求/响应还原、进程归因 |
| 界面 | 三栏式（报文列表 / 协议详情树 / 十六进制），深色主题，支持离线 pcap 回放 |

## 运行

```powershell
# 1. 安装依赖
python -m pip install -r requirements.txt

# 2. 安装 Npcap（实时抓包必需，安装时勾选 WinPcap API 兼容模式）
#    https://npcap.com

# 3. 启动
python main.py
# 或直接打开演示抓包：
python main.py demo\demo.pcap
```

实时抓包需要**管理员权限**（Npcap 驱动访问）。

## 目录结构

```
main.py                 程序入口
app/
  core/
    capture.py          网卡枚举 + AsyncSniffer 封装 + 队列
    dissector.py        协议解析（列表摘要 + OSI 逐层协议树）
    protocols.py        HTTP / TLS SNI / DNS 应用层解析
    filter_engine.py    显示过滤器（词法 → 语法 → 求值）
    flows.py            TCP 流重组 + HTTP 事务还原
    proc_map.py         psutil 端口 → 进程归因
    stats.py            协议分层 / 会话 / 吞吐统计
    pcap_io.py          pcap 读写
  ui/
    main_window.py      主窗口（三栏布局、菜单、状态栏）
    packet_model.py     报文列表数据模型
    detail_tree.py      协议详情树
    hexview.py          十六进制视图
    dialogs.py          统计 / 流追踪 / 语法帮助 / 关于
    theme.py            深色主题 QSS
tests/test_core.py      16 项核心逻辑单元测试
tools/                  演示抓包生成、截图、报告生成
demo/demo.pcap          离线演示抓包
```

## 测试

```powershell
python -m unittest discover -s tests -v
```

## 说明

仅用于**已获授权**的网络环境下的教学与研究。对 HTTPS 只能解析到 TLS 握手层的
SNI，不对加密载荷做任何解密。
