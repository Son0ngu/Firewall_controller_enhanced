"""Qt style sheet (QSS) for the SAINT agent GUI.

Colours are referenced as constants so view code can pull them into inline
styles for status-driven colour changes.
"""

# Palette
BG_WINDOW = "#F6F8FB"        # Main window background
BG_CARD = "#FFFFFF"          # Cards / panels
BG_INPUT = "#FFFFFF"         # Entries, textboxes
BG_HOVER = "#F1F5F9"
BG_ACTIVE = "#EAF4FF"
BG_TABLE_HEADER = "#F8FAFC"

FG_PRIMARY = "#0F172A"       # Main text
FG_SECONDARY = "#475569"     # Subtitles
FG_MUTED = "#94A3B8"

ACCENT_BLUE = "#0B78D0"
ACCENT_GREEN = "#16A34A"
ACCENT_RED = "#DC2626"
ACCENT_ORANGE = "#D97706"
ACCENT_PURPLE = "#2563EB"

BORDER_LIGHT = "#E2E8F0"

# Status colour helpers - used by status cards / log banners
STATUS_COLORS = {
    "ok": ACCENT_GREEN,
    "running": ACCENT_GREEN,
    "online": ACCENT_GREEN,
    "active": ACCENT_GREEN,
    "stopped": "#888888",
    "offline": ACCENT_RED,
    "error": ACCENT_RED,
    "blocked": ACCENT_RED,
    "starting": ACCENT_ORANGE,
    "stopping": ACCENT_ORANGE,
    "degraded": ACCENT_ORANGE,
    "syncing": ACCENT_ORANGE,
    "pending": ACCENT_ORANGE,
}


# Global QSS applied to QApplication. Per-widget overrides happen in the
# widget classes themselves so this stylesheet stays readable.
GLOBAL_QSS = f"""
QWidget {{
    background-color: {BG_WINDOW};
    color: {FG_PRIMARY};
    font-family: "Segoe UI", "San Francisco", sans-serif;
    font-size: 13px;
}}

/* QLabel inherits the QWidget rule above by default, which paints a window-
 * coloured rectangle behind every label - including labels sitting INSIDE a
 * coloured card frame, producing an ugly "tiled" look. Make labels transparent
 * so they pick up their parent panel's background instead. */
QLabel {{
    background-color: transparent;
}}

QFrame#card {{
    background-color: {BG_CARD};
    border-radius: 8px;
    border: 1px solid {BORDER_LIGHT};
}}

QFrame#sidebar {{
    background-color: #FFFFFF;
    border-right: 1px solid {BORDER_LIGHT};
}}

QPushButton {{
    background-color: #F8FAFC;
    color: {FG_PRIMARY};
    border: 1px solid {BORDER_LIGHT};
    border-radius: 8px;
    padding: 8px 14px;
    font-weight: 600;
}}
QPushButton:hover {{
    background-color: {BG_HOVER};
}}
QPushButton:disabled {{
    color: {FG_MUTED};
}}

QPushButton#sidebar_item {{
    background-color: transparent;
    text-align: left;
    padding: 10px 14px;
    border-radius: 8px;
    border: 1px solid transparent;
    color: {FG_SECONDARY};
    font-weight: 600;
}}
QPushButton#sidebar_item:hover {{
    background-color: {BG_HOVER};
    color: {FG_PRIMARY};
}}
QPushButton#sidebar_item:checked {{
    background-color: {BG_ACTIVE};
    color: {ACCENT_BLUE};
    border-left: 3px solid {ACCENT_BLUE};
}}

QPushButton#primary {{
    background-color: {ACCENT_BLUE};
    color: white;
}}
QPushButton#primary:hover {{
    background-color: #075EA8;
}}

QPushButton#success {{
    background-color: {ACCENT_GREEN};
    color: white;
}}
QPushButton#success:hover {{
    background-color: #15803D;
}}

QPushButton#danger {{
    background-color: {ACCENT_RED};
    color: white;
}}
QPushButton#danger:hover {{
    background-color: #B91C1C;
}}

QLineEdit, QPlainTextEdit, QTextEdit, QComboBox {{
    background-color: {BG_INPUT};
    border: 1px solid {BORDER_LIGHT};
    border-radius: 8px;
    padding: 6px 8px;
    color: {FG_PRIMARY};
}}
QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus, QComboBox:focus {{
    border-color: {ACCENT_BLUE};
}}

QComboBox::drop-down {{
    border: 0;
    width: 24px;
}}

QPlainTextEdit#activity_log {{
    background-color: {BG_INPUT};
    font-family: "Consolas", "Courier New", monospace;
    font-size: 11px;
}}

QLabel#title {{
    font-size: 24px;
    font-weight: bold;
    color: {FG_PRIMARY};
}}

QLabel#card_title {{
    color: {FG_SECONDARY};
    font-size: 12px;
}}

QLabel#card_value {{
    font-size: 24px;
    font-weight: bold;
    color: {FG_PRIMARY};
}}

QLabel#card_subtitle {{
    color: {FG_MUTED};
    font-size: 11px;
}}

QHeaderView::section {{
    background-color: {BG_TABLE_HEADER};
    color: {FG_SECONDARY};
    border: 0;
    border-bottom: 1px solid {BORDER_LIGHT};
    padding: 9px 10px;
    font-weight: bold;
}}

QTableView {{
    background-color: {BG_INPUT};
    alternate-background-color: #FBFDFF;
    gridline-color: {BORDER_LIGHT};
    border: 0;
    selection-background-color: {BG_ACTIVE};
    selection-color: {FG_PRIMARY};
}}
"""
