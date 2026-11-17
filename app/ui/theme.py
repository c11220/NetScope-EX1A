"""界面主题：深色专业配色 + 各协议的标识色。"""

from __future__ import annotations

from PySide6.QtGui import QColor

COLORS = {
    "bg": "#1b1d21",
    "panel": "#232629",
    "panel_alt": "#2a2d31",
    "border": "#34383d",
    "text": "#d8dbe0",
    "muted": "#8b9199",
    "accent": "#3f8cff",
    "accent_dim": "#2f6fd0",
    "danger": "#ef5350",
    "ok": "#4caf7d",
    "warn": "#e0a33c",
}

PROTOCOL_COLORS: dict[str, str] = {
    "TCP": "#6ab0f3",
    "UDP": "#e0b25c",
    "HTTP": "#59c98a",
    "TLS": "#f28b82",
    "HTTPS": "#f28b82",
    "DNS": "#c58af9",
    "ICMP": "#f7c948",
    "ICMPv6": "#f7c948",
    "ARP": "#b6c2cf",
    "DHCP": "#7fd1c8",
    "SSH": "#ff9f6e",
    "IPv4": "#9fb3c8",
    "IPv6": "#9fb3c8",
    "MALFORMED": "#ef5350",
}


def color_for(proto: str) -> QColor:
    return QColor(PROTOCOL_COLORS.get(proto, "#a9b2bd"))


MONO_FONT = "'Cascadia Mono', 'Consolas', 'JetBrains Mono', 'Courier New'"
UI_FONT = "'Microsoft YaHei UI', 'Segoe UI', 'PingFang SC'"


def stylesheet() -> str:
    c = COLORS
    return f"""
    QWidget {{
        background: {c['bg']};
        color: {c['text']};
        font-family: {UI_FONT};
        font-size: 12px;
    }}
    QMainWindow::separator {{
        background: {c['border']};
        width: 1px;
        height: 1px;
    }}
    QMenuBar {{
        background: {c['panel']};
        border-bottom: 1px solid {c['border']};
        padding: 2px 6px;
    }}
    QMenuBar::item {{ padding: 5px 10px; border-radius: 4px; background: transparent; }}
    QMenuBar::item:selected {{ background: {c['panel_alt']}; }}
    QMenu {{
        background: {c['panel']};
        border: 1px solid {c['border']};
        padding: 4px;
    }}
    QMenu::item {{ padding: 6px 24px 6px 16px; border-radius: 4px; }}
    QMenu::item:selected {{ background: {c['accent_dim']}; }}
    QMenu::separator {{ height: 1px; background: {c['border']}; margin: 4px 8px; }}

    QFrame#Toolbar {{
        background: {c['panel']};
        border-bottom: 1px solid {c['border']};
    }}
    QFrame#FilterBar {{
        background: {c['panel_alt']};
        border-bottom: 1px solid {c['border']};
    }}

    QLabel {{ background: transparent; }}
    QLabel#Hint {{ color: {c['muted']}; }}
    QLabel#Badge {{
        background: {c['panel_alt']};
        border: 1px solid {c['border']};
        border-radius: 9px;
        padding: 2px 9px;
        color: {c['muted']};
    }}

    QPushButton {{
        background: {c['panel_alt']};
        border: 1px solid {c['border']};
        border-radius: 5px;
        padding: 6px 14px;
    }}
    QPushButton:hover {{ background: #33373c; border-color: #444a51; }}
    QPushButton:pressed {{ background: #1f2226; }}
    QPushButton:disabled {{ color: #5c626a; background: #24272a; }}
    QPushButton#Primary {{
        background: {c['accent_dim']};
        border-color: {c['accent']};
        color: #ffffff;
        font-weight: 600;
    }}
    QPushButton#Primary:hover {{ background: {c['accent']}; }}
    QPushButton#Danger {{
        background: #5a2a2a; border-color: #8c3b3b; color: #ffd7d7; font-weight: 600;
    }}
    QPushButton#Danger:hover {{ background: #7a3232; }}

    QLineEdit, QComboBox, QSpinBox {{
        background: {c['panel']};
        border: 1px solid {c['border']};
        border-radius: 5px;
        padding: 6px 9px;
        selection-background-color: {c['accent_dim']};
    }}
    QLineEdit:focus, QComboBox:focus {{ border-color: {c['accent']}; }}
    QLineEdit#Filter {{
        background: #1a2330;
        border: 1px solid #2c4a72;
        font-family: {MONO_FONT};
    }}
    QLineEdit#Filter[invalid="true"] {{
        border-color: {c['danger']};
        background: #2a1c1c;
    }}
    QComboBox::drop-down {{ border: none; width: 20px; }}
    QComboBox QAbstractItemView {{
        background: {c['panel']};
        border: 1px solid {c['border']};
        selection-background-color: {c['accent_dim']};
        outline: none;
    }}
    QCheckBox {{ spacing: 6px; }}
    QCheckBox::indicator {{
        width: 14px; height: 14px; border-radius: 3px;
        border: 1px solid {c['border']}; background: {c['panel']};
    }}
    QCheckBox::indicator:checked {{ background: {c['accent']}; border-color: {c['accent']}; }}

    QTableView {{
        background: {c['bg']};
        alternate-background-color: #1f2125;
        gridline-color: {c['border']};
        border: none;
        font-family: {MONO_FONT};
        selection-background-color: #24456f;
        selection-color: #ffffff;
        outline: none;
    }}
    QHeaderView::section {{
        background: {c['panel']};
        color: {c['muted']};
        border: none;
        border-right: 1px solid {c['border']};
        border-bottom: 1px solid {c['border']};
        padding: 6px 8px;
        font-weight: 600;
    }}
    QTableCornerButton::section {{ background: {c['panel']}; border: none; }}

    QTreeWidget, QTreeView {{
        background: {c['bg']};
        border: none;
        font-family: {MONO_FONT};
        selection-background-color: #24456f;
        outline: none;
    }}
    QTreeWidget::item, QTreeView::item {{ padding: 2px 0; }}
    QTreeWidget::item:hover, QTreeView::item:hover {{ background: #24272b; }}

    QTabWidget::pane {{
        border: 1px solid {c['border']};
        border-bottom: none;
        background: {c['bg']};
    }}
    QTabBar::tab {{
        background: {c['panel']};
        color: {c['muted']};
        border: 1px solid {c['border']};
        border-bottom: none;
        padding: 6px 16px;
        margin-right: 2px;
        border-top-left-radius: 5px;
        border-top-right-radius: 5px;
    }}
    QTabBar::tab:selected {{ background: {c['bg']}; color: {c['text']}; }}
    QTabBar::tab:hover {{ color: {c['text']}; }}

    QStatusBar {{
        background: {c['panel']};
        border-top: 1px solid {c['border']};
        color: {c['muted']};
    }}
    QStatusBar::item {{ border: none; }}

    QScrollBar:vertical {{ background: {c['bg']}; width: 11px; margin: 0; }}
    QScrollBar::handle:vertical {{ background: #3a3f45; min-height: 24px; border-radius: 5px; }}
    QScrollBar::handle:vertical:hover {{ background: #4a5058; }}
    QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; }}
    QScrollBar:horizontal {{ background: {c['bg']}; height: 11px; margin: 0; }}
    QScrollBar::handle:horizontal {{ background: #3a3f45; min-width: 24px; border-radius: 5px; }}
    QScrollBar::handle:horizontal:hover {{ background: #4a5058; }}
    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}

    QSplitter::handle {{ background: {c['border']}; }}
    QSplitter::handle:vertical {{ height: 2px; }}
    QToolTip {{
        background: {c['panel']};
        color: {c['text']};
        border: 1px solid {c['border']};
        padding: 4px 6px;
    }}
    QDialog {{ background: {c['panel']}; }}
    QGroupBox {{
        border: 1px solid {c['border']};
        border-radius: 6px;
        margin-top: 12px;
        padding-top: 8px;
    }}
    QGroupBox::title {{ subcontrol-origin: margin; left: 10px; padding: 0 4px; color: {c['muted']}; }}
    QProgressBar {{
        border: 1px solid {c['border']}; border-radius: 4px; text-align: center;
        background: {c['bg']};
    }}
    QProgressBar::chunk {{ background: {c['accent_dim']}; border-radius: 3px; }}
    """
