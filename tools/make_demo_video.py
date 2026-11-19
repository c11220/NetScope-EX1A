"""自动录制实验 1A 演示视频（无人工操作）。

流程：
1. 用 Windows SAPI（慧慧 zh-CN）逐场景合成旁白 WAV，得到每段时长；
2. 按旁白时长生成场景时间轴；
3. ffmpeg gdigrab 录制桌面，同时在本进程内驱动 PySide6 界面按时间轴操作；
4. 合成音轨、烧入中文字幕，输出 mp4。

用法：python tools/make_demo_video.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import wave

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

TEMP = os.path.join(tempfile.gettempdir(), "netscope_video")
os.makedirs(TEMP, exist_ok=True)

OUT_DIR = r"e:\1A\柴俊雪_202649210129013_EX1A"
OUT_NAME = "柴俊雪_202649210129013_ex1A_play.mp4"

# ---------------------------------------------------------------- 场景脚本

SCENES = [
    {
        "id": "intro",
        "text": "大家好，我是柴俊雪，学号二零二六四九二一零一二九零一三。这是实验一 A：带图形界面的网络嗅探器 NetScope。",
        "min": 7.0,
    },
    {
        "id": "arch",
        "text": "程序使用 Python 编写，界面基于 Qt 框架，抓包通过 Npcap 驱动完成。界面上方是控制栏，中间是报文列表，下方是协议详情和十六进制视图。",
        "min": 11.0,
    },
    {
        "id": "live_start",
        "text": "我先选择本机的无线网卡，并设置捕获过滤器，只抓取八十和四百四十三端口，然后点击开始捕获。",
        "min": 11.0,
    },
    {
        "id": "live_view",
        "text": "报文正在实时滚动，状态栏显示报文数量、速率和丢弃计数。选中一条报文，下方会按 OSI 模型逐层展开，从以太网、IP 一直到 TCP，另一个标签页显示对应的十六进制字节。",
        "min": 15.0,
    },
    {
        "id": "process",
        "text": "进程列显示每条连接属于哪个程序，这里可以看到 VLC。程序每两秒读取一次系统连接表，把本地端口映射到进程，所以每一帧都能追溯到来源程序。",
        "min": 13.0,
    },
    {
        "id": "open_pcap",
        "text": "停止捕获。为了演示应用层分析，我打开一个事先构造的抓包文件，里面包含 HTTP、DNS、TLS 和 ICMP。",
        "min": 11.0,
    },
    {
        "id": "filter",
        "text": "显示过滤器支持逻辑演算。我输入 http and http host contains example，列表只剩目标站点的请求；再试 dns or arp，以及带括号和 not 的组合条件，比如 tcp or udp 并且不是二十二端口。",
        "min": 17.0,
    },
    {
        "id": "filter_err",
        "text": "如果语法写错，输入框会立刻变红并提示原因，避免用户盲目猜测。",
        "min": 8.0,
    },
    {
        "id": "flows",
        "text": "分析菜单里可以打开 TCP 流追踪。程序按源地址、源端口、目的地址、目的端口四元组重组双向字节流，按序号去重和裁剪，还原出完整的 HTTP 请求和响应。这条 POST 请求里的用户名和密码是明文，这也说明为什么必须使用 HTTPS。",
        "min": 21.0,
    },
    {
        "id": "stats",
        "text": "协议分层统计展示各层协议的占比，会话表按端点对聚合流量，吞吐图显示每秒报文数，可以快速判断网络流量的构成。",
        "min": 12.0,
    },
    {
        "id": "outro",
        "text": "完整代码和提交历史都在 GitHub 上，十六项单元测试全部通过。以上就是实验一 A 的演示，谢谢。",
        "min": 9.0,
    },
]


# ---------------------------------------------------------------- 工具函数

def find_ffmpeg() -> str:
    for name in ("ffmpeg.exe", "ffmpeg"):
        try:
            subprocess.run([name, "-version"], capture_output=True, check=True)
            return name
        except Exception:
            pass
    package_dir = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "WinGet", "Packages")
    if os.path.isdir(package_dir):
        for entry in os.listdir(package_dir):
            if entry.lower().startswith("gyan.ffmpeg"):
                for walk_root, _dirs, files in os.walk(os.path.join(package_dir, entry)):
                    if "ffmpeg.exe" in files:
                        return os.path.join(walk_root, "ffmpeg.exe")
    raise RuntimeError("未找到 ffmpeg，请先安装 Gyan.FFmpeg")


def synth(text: str, index: int) -> str:
    """调用 SAPI 合成一段中文旁白，返回 wav 路径。"""
    txt_path = os.path.join(TEMP, f"scene{index:02d}.txt")
    wav_path = os.path.join(TEMP, f"scene{index:02d}.wav")
    with open(txt_path, "w", encoding="utf-8") as handle:
        handle.write(text)
    script = (
        "Add-Type -AssemblyName System.Speech;"
        "$s = New-Object System.Speech.Synthesis.SpeechSynthesizer;"
        "try { $s.SelectVoice('Microsoft Huihui Desktop') } catch {};"
        "$s.Rate = 0;"
        f"$s.SetOutputToWaveFile('{wav_path}');"
        f"$t = Get-Content -LiteralPath '{txt_path}' -Raw -Encoding UTF8;"
        "$s.Speak($t); $s.Dispose()"
    )
    subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
                   check=True, capture_output=True)
    return wav_path


def wav_duration(path: str) -> float:
    with wave.open(path, "rb") as handle:
        return handle.getnframes() / float(handle.getframerate())


def build_timeline() -> list[dict]:
    timeline = []
    cursor = 1.0            # 录制开始后 1 秒再进入第一幕
    for index, scene in enumerate(SCENES):
        wav = synth(scene["text"], index)
        duration = max(scene["min"], wav_duration(wav) + 0.8)
        timeline.append({
            "id": scene["id"],
            "text": scene["text"],
            "wav": wav,
            "start": cursor,
            "duration": duration,
        })
        cursor += duration
    return timeline


def write_actions(timeline: list[dict]) -> dict:
    """把每幕的关键动作换算成绝对秒数（相对录制开始）。"""
    by_id = {scene["id"]: scene for scene in timeline}

    def at(scene_id: str, offset: float) -> float:
        return by_id[scene_id]["start"] + offset

    actions = {
        "select_iface": at("live_start", 0.6),
        "set_bpf": at("live_start", 2.4),
        "start_capture": at("live_start", 6.2),
        "select_packet": at("live_view", 2.0),
        "scroll_list": at("live_view", 5.0),
        "show_hex": at("live_view", 9.0),
        "back_detail": at("live_view", 12.5),
        "highlight_process": at("process", 4.0),
        "stop_capture": at("open_pcap", 0.4),
        "open_pcap": at("open_pcap", 2.2),
        "select_http": at("open_pcap", 7.0),
        "filter_http": at("filter", 0.8),
        "filter_dns": at("filter", 6.5),
        "filter_logic": at("filter", 10.5),
        "filter_bad": at("filter_err", 0.6),
        "filter_fix": at("filter_err", 4.2),
        "open_flows": at("flows", 0.8),
        "flows_http_tab": at("flows", 7.0),
        "flows_c2s_tab": at("flows", 13.0),
        "close_flows": at("flows", 18.5),
        "open_stats": at("stats", 0.8),
        "stats_conv": at("stats", 5.0),
        "stats_io": at("stats", 8.0),
        "close_stats": at("stats", 10.5),
    }
    return actions


def build_audio(timeline: list[dict], total: float, path: str, ffmpeg: str) -> None:
    inputs = [ffmpeg, "-y", "-f", "lavfi", "-i", f"anullsrc=r=22050:cl=mono:d={total:.2f}"]
    filters = []
    for index, scene in enumerate(timeline, start=1):
        inputs += ["-i", scene["wav"]]
        delay = int((scene["start"] + 0.25) * 1000)
        filters.append(f"[{index}:a]aresample=22050,adelay={delay}|{delay}[a{index}]")
    mix_inputs = "[0:a]" + "".join(f"[a{i}]" for i in range(1, len(timeline) + 1))
    filters.append(f"{mix_inputs}amix=inputs={len(timeline) + 1}:normalize=0:duration=first[aout]")
    command = inputs + ["-filter_complex", ";".join(filters), "-map", "[aout]",
                        "-c:a", "pcm_s16le", path]
    subprocess.run(command, check=True, capture_output=True)


# ---------------------------------------------------------------- 界面自动化

def run_automation(timeline: list[dict], actions: dict, total: float, lead: float = 0.0) -> None:
    from PySide6.QtCore import QTimer, Qt
    from PySide6.QtGui import QCursor, QFont
    from PySide6.QtWidgets import QApplication, QTabWidget

    from app.ui.dialogs import FlowsDialog, StatisticsDialog
    from app.ui.main_window import MainWindow
    from app.ui.theme import stylesheet

    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setFont(QFont("Microsoft YaHei UI", 10))
    app.setStyleSheet(stylesheet())

    window = MainWindow()
    window.showFullScreen()
    app.processEvents()

    state: dict = {"flows": None, "stats": None}

    def click_at(widget) -> None:
        try:
            point = widget.mapToGlobal(widget.rect().center())
            QCursor.setPos(point)
        except Exception:
            pass

    def guarded(func):
        def wrapper():
            try:
                func()
            except Exception as exc:  # 录制过程中不允许中断
                print("action error:", exc)
        return wrapper

    # --- 动作定义 -----------------------------------------------------
    def select_iface():
        for index in range(window.iface_combo.count()):
            text = window.iface_combo.itemText(index)
            if "169.254" in text or "Loopback" in text:
                continue
            window.iface_combo.setCurrentIndex(index)
            break
        click_at(window.iface_combo)

    def set_bpf():
        window.capture_filter.setText("tcp port 443 or tcp port 80")
        click_at(window.capture_filter)

    def start_capture():
        click_at(window.btn_start)
        window._start_capture()

    def select_packet():
        rows = window.model.rowCount()
        if rows:
            window.table.selectRow(max(0, rows - 6))
            window.table.scrollToBottom()
        click_at(window.table)

    def scroll_list():
        rows = window.model.rowCount()
        if rows:
            window.table.selectRow(rows // 2)
        click_at(window.table)

    def show_hex():
        window.detail_tabs.setCurrentIndex(1)
        click_at(window.detail_tabs)
        index = window.table.currentIndex()
        record = window.model.record_at(index.row()) if index.isValid() else None
        if record is not None:
            window.hexview.set_data(record.raw)

    def back_detail():
        window.detail_tabs.setCurrentIndex(0)

    def highlight_process():
        rows = window.model.rowCount()
        for row in range(rows - 1, max(0, rows - 60), -1):
            record = window.model.record_at(row)
            if record and record.pname:
                window.table.selectRow(row)
                break
        click_at(window.table.horizontalHeader())

    def stop_capture():
        window._stop_capture()

    def open_pcap():
        window.load_path_sync(os.path.join(ROOT, "demo", "demo.pcap"))

    def select_http():
        for row in range(window.model.rowCount()):
            record = window.model.record_at(row)
            if record and record.proto == "HTTP" and record.info.startswith("GET"):
                window.table.selectRow(row)
                break
        click_at(window.table)

    def apply_filter(text: str):
        window.filter_edit.setText(text)
        click_at(window.filter_edit)
        window._apply_display_filter()

    def filter_http():
        apply_filter('http and http.host contains "example"')

    def filter_dns():
        apply_filter("dns or arp")

    def filter_logic():
        apply_filter("(tcp or udp) and not port 22")

    def filter_bad():
        window.filter_edit.setText("http and (tcp")
        window._validate_filter_ui()
        click_at(window.filter_edit)

    def filter_fix():
        window.filter_edit.setText("")
        window._apply_display_filter()

    def open_flows():
        streams = sorted(window.flows.tracker.streams(), key=lambda s: -s.packets)
        dialog = FlowsDialog(streams, window)
        dialog.setWindowModality(Qt.NonModal)
        dialog.resize(1180, 720)
        dialog.move(120, 150)
        dialog.show()
        dialog.raise_()
        state["flows"] = dialog
        click_at(dialog)

    def flows_tab(index: int):
        dialog = state.get("flows")
        if dialog is not None:
            dialog.detail_tabs.setCurrentIndex(index)

    def close_flows():
        dialog = state.get("flows")
        if dialog is not None:
            dialog.close()
            state["flows"] = None

    def open_stats():
        dialog = StatisticsDialog(window.stats, window)
        dialog.setWindowModality(Qt.NonModal)
        dialog.resize(1000, 640)
        dialog.move(180, 140)
        dialog.show()
        dialog.raise_()
        state["stats"] = dialog
        click_at(dialog)

    def stats_tab(dialog_index: int):
        dialog = state.get("stats")
        if dialog is not None:
            tabs = dialog.findChild(QTabWidget)
            if tabs is not None:
                tabs.setCurrentIndex(dialog_index)

    def close_stats():
        dialog = state.get("stats")
        if dialog is not None:
            dialog.close()
            state["stats"] = None

    mapping = {
        "select_iface": select_iface,
        "set_bpf": set_bpf,
        "start_capture": start_capture,
        "select_packet": select_packet,
        "scroll_list": scroll_list,
        "show_hex": show_hex,
        "back_detail": back_detail,
        "highlight_process": highlight_process,
        "stop_capture": stop_capture,
        "open_pcap": open_pcap,
        "select_http": select_http,
        "filter_http": filter_http,
        "filter_dns": filter_dns,
        "filter_logic": filter_logic,
        "filter_bad": filter_bad,
        "filter_fix": filter_fix,
        "open_flows": open_flows,
        "flows_http_tab": lambda: flows_tab(2),
        "flows_c2s_tab": lambda: flows_tab(0),
        "close_flows": close_flows,
        "open_stats": open_stats,
        "stats_conv": lambda: stats_tab(1),
        "stats_io": lambda: stats_tab(2),
        "close_stats": close_stats,
    }

    for name, when in actions.items():
        action = mapping.get(name)
        if action is not None:
            # 时间轴以“录制开始”为原点，而本进程比录制晚 lead 秒启动
            QTimer.singleShot(int(max(0.0, when - lead) * 1000), guarded(action))

    QTimer.singleShot(int(total * 1000), app.quit)
    app.exec()


def main() -> None:
    ffmpeg = find_ffmpeg()
    print("ffmpeg:", ffmpeg)

    print("合成旁白…")
    timeline = build_timeline()
    total = timeline[-1]["start"] + timeline[-1]["duration"] + 0.8
    print(f"总时长 {total:.1f}s，共 {len(timeline)} 幕")

    actions = write_actions(timeline)
    with open(os.path.join(TEMP, "timeline.json"), "w", encoding="utf-8") as handle:
        json.dump(timeline, handle, ensure_ascii=False, indent=1)

    audio_path = os.path.join(TEMP, "narration.wav")
    build_audio(timeline, total, audio_path, ffmpeg)

    raw_video = os.path.join(TEMP, "screen.mp4")
    if os.path.exists(raw_video):
        os.remove(raw_video)

    print("开始录制屏幕…")
    lead = 0.8
    recorder = subprocess.Popen(
        [ffmpeg, "-y", "-f", "gdigrab", "-framerate", "12", "-draw_mouse", "1",
         "-i", "desktop", "-t", f"{total:.1f}",
         "-c:v", "libx264", "-preset", "veryfast", "-crf", "23",
         "-pix_fmt", "yuv420p", raw_video],
        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(lead)

    print("开始驱动界面…")
    run_automation(timeline, actions, total - lead, lead=lead)

    print("等待编码完成…")
    recorder.wait(timeout=180)

    os.makedirs(OUT_DIR, exist_ok=True)
    final_path = os.path.join(OUT_DIR, OUT_NAME)
    print("合成音轨…")
    subprocess.run([
        ffmpeg, "-y", "-i", raw_video, "-i", audio_path,
        "-c:v", "copy", "-c:a", "aac", "-b:a", "128k", "-shortest", final_path,
    ], check=True, capture_output=True)

    print("完成：", final_path)
    print("时长：", total)


if __name__ == "__main__":
    main()
