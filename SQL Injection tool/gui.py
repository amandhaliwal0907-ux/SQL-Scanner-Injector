
# gui.py - SQLi Scout Desktop Application
# Clean, modern PyQt5 interface

import sys
import os
import json
import time
import threading
from datetime import datetime

try:
    from payload_lab import PayloadLabTab
    HAS_PAYLOAD_LAB = True
except ImportError:
    HAS_PAYLOAD_LAB = False

try:
    from quick_launch import QuickLaunchTab
    HAS_QUICK_LAUNCH = True
except ImportError:
    HAS_QUICK_LAUNCH = False

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QCheckBox, QSpinBox, QDoubleSpinBox,
    QTextEdit, QTableWidget, QTableWidgetItem, QTabWidget, QFrame,
    QSplitter, QGroupBox, QComboBox, QFileDialog, QProgressBar,
    QHeaderView, QScrollArea, QSizePolicy, QAbstractItemView,
    QStatusBar, QToolTip, QMessageBox
)
from PyQt5.QtCore import (
    Qt, QThread, pyqtSignal, QTimer, QSize, QPropertyAnimation, QEasingCurve
)
from PyQt5.QtGui import (
    QFont, QColor, QPalette, QIcon, QPixmap, QPainter,
    QLinearGradient, QBrush, QPen, QFontDatabase
)


# Color Palette

class Colors:
    # Backgrounds - unified dark theme
    BG_APP       = "#0F1623"   # outermost
    BG_SIDEBAR   = "#141C2B"   # sidebar
    BG_CONTENT   = "#1A2235"   # main content area
    BG_CARD      = "#212D42"   # cards, panels
    BG_INPUT     = "#1E2A3C"   # input fields
    BG_HOVER     = "#263347"   # hover states
    BG_ROW_ALT   = "#1D2A3D"   # alternating table rows

    # Keep old names mapped to new palette for compat
    BG_PRIMARY   = "#1A2235"
    BG_SECONDARY = "#212D42"
    BG_TERTIARY  = "#263347"

    # Accents
    ACCENT       = "#4C8EF7"
    ACCENT_HOVER = "#6BA3F9"
    ACCENT_LIGHT = "#1E3A6E"
    SUCCESS      = "#34D399"
    WARNING      = "#FBBF24"
    DANGER       = "#F87171"
    CRITICAL     = "#A78BFA"

    # Text
    TEXT_PRIMARY   = "#E2E8F0"
    TEXT_SECONDARY = "#94A3B8"
    TEXT_MUTED     = "#64748B"
    TEXT_SIDEBAR   = "#94A3B8"
    TEXT_SIDEBAR_H = "#E2E8F0"

    # Borders
    BORDER       = "#2A3A52"
    BORDER_FOCUS = "#4C8EF7"

    # Severity
    SEV_CRITICAL = "#A78BFA"
    SEV_HIGH     = "#F87171"
    SEV_MEDIUM   = "#FBBF24"
    SEV_LOW      = "#4C8EF7"
    SEV_INFO     = "#64748B"

SEVERITY_BG = {
    "CRITICAL": "#2D1F4E",
    "HIGH":     "#3D1F1F",
    "MEDIUM":   "#3D2E0A",
    "LOW":      "#1E3A6E",
    "INFO":     "#263347",
}
SEVERITY_FG = {
    "CRITICAL": Colors.SEV_CRITICAL,
    "HIGH":     Colors.SEV_HIGH,
    "MEDIUM":   Colors.SEV_MEDIUM,
    "LOW":      Colors.SEV_LOW,
    "INFO":     Colors.SEV_INFO,
}


# Stylesheet

STYLESHEET = f"""
QMainWindow, QWidget {{
    background-color: {Colors.BG_CONTENT};
    color: {Colors.TEXT_PRIMARY};
    font-family: "Segoe UI", Arial, sans-serif;
    font-size: 13px;
}}

/* ── Sidebar ── */
#sidebar {{
    background-color: {Colors.BG_SIDEBAR};
}}
#sidebar QLabel {{
    color: {Colors.TEXT_SIDEBAR};
    background: transparent;
}}
#appTitle {{
    color: #FFFFFF;
    font-size: 16px;
    font-weight: 700;
    background: transparent;
}}
#appSubtitle {{
    color: {Colors.TEXT_MUTED};
    font-size: 11px;
    background: transparent;
}}
#sidebarSection {{
    color: {Colors.TEXT_MUTED};
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 1.5px;
    padding: 4px 0px;
    background: transparent;
}}

/* ── Inputs ── */
QLineEdit, QSpinBox, QDoubleSpinBox, QComboBox {{
    background-color: {Colors.BG_INPUT};
    border: 1px solid {Colors.BORDER};
    border-radius: 6px;
    padding: 6px 10px;
    color: {Colors.TEXT_PRIMARY};
    font-size: 13px;
    selection-background-color: {Colors.ACCENT};
}}
QLineEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus, QComboBox:focus {{
    border-color: {Colors.BORDER_FOCUS};
}}
QLineEdit:disabled, QSpinBox:disabled {{
    background-color: {Colors.BG_CARD};
    color: {Colors.TEXT_MUTED};
}}
QComboBox::drop-down {{
    border: none;
    width: 24px;
}}
QComboBox::down-arrow {{
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 5px solid {Colors.TEXT_SECONDARY};
    margin-right: 8px;
}}
QComboBox QAbstractItemView {{
    background: {Colors.BG_CARD};
    border: 1px solid {Colors.BORDER};
    border-radius: 6px;
    selection-background-color: {Colors.ACCENT_LIGHT};
    selection-color: {Colors.TEXT_PRIMARY};
    color: {Colors.TEXT_PRIMARY};
}}
QSpinBox::up-button, QSpinBox::down-button,
QDoubleSpinBox::up-button, QDoubleSpinBox::down-button {{
    width: 18px;
    border: none;
    background: {Colors.BG_HOVER};
}}
QSpinBox::up-arrow, QDoubleSpinBox::up-arrow {{
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-bottom: 5px solid {Colors.TEXT_SECONDARY};
}}
QSpinBox::down-arrow, QDoubleSpinBox::down-arrow {{
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 5px solid {Colors.TEXT_SECONDARY};
}}

/* ── Buttons ── */
QPushButton {{
    border-radius: 7px;
    padding: 7px 16px;
    font-size: 13px;
    font-weight: 500;
    border: none;
    color: {Colors.TEXT_PRIMARY};
    background-color: {Colors.BG_HOVER};
}}
QPushButton:hover {{
    background-color: {Colors.BORDER};
}}
QPushButton#primaryBtn {{
    background-color: {Colors.ACCENT};
    color: white;
    padding: 10px 24px;
    font-size: 14px;
    font-weight: 600;
    border-radius: 8px;
    min-height: 40px;
}}
QPushButton#primaryBtn:hover {{
    background-color: {Colors.ACCENT_HOVER};
}}
QPushButton#primaryBtn:disabled {{
    background-color: {Colors.BG_HOVER};
    color: {Colors.TEXT_MUTED};
}}
QPushButton#dangerBtn {{
    background-color: {Colors.DANGER};
    color: white;
    padding: 10px 24px;
    font-size: 14px;
    font-weight: 600;
    border-radius: 8px;
    min-height: 40px;
}}
QPushButton#dangerBtn:hover {{
    background-color: #EF4444;
}}
QPushButton#secondaryBtn {{
    background-color: {Colors.BG_CARD};
    color: {Colors.TEXT_PRIMARY};
    border: 1px solid {Colors.BORDER};
}}
QPushButton#secondaryBtn:hover {{
    border-color: {Colors.ACCENT};
    color: {Colors.ACCENT};
}}
QPushButton#iconBtn {{
    background-color: {Colors.BG_CARD};
    color: {Colors.TEXT_SECONDARY};
    padding: 6px 12px;
    font-size: 12px;
    border: 1px solid {Colors.BORDER};
}}
QPushButton#iconBtn:hover {{
    background-color: {Colors.ACCENT_LIGHT};
    color: {Colors.ACCENT};
    border-color: {Colors.ACCENT};
}}

/* ── Checkboxes ── */
QCheckBox {{
    color: {Colors.TEXT_SIDEBAR};
    spacing: 8px;
    font-size: 13px;
    background: transparent;
}}
QCheckBox::indicator {{
    width: 15px;
    height: 15px;
    border-radius: 4px;
    border: 1.5px solid {Colors.BORDER};
    background: {Colors.BG_INPUT};
}}
QCheckBox::indicator:checked {{
    background-color: {Colors.ACCENT};
    border-color: {Colors.ACCENT};
}}
QCheckBox::indicator:hover {{
    border-color: {Colors.ACCENT};
}}

/* ── Tabs ── */
QTabWidget::pane {{
    border: 1px solid {Colors.BORDER};
    border-radius: 8px;
    background: {Colors.BG_CONTENT};
    top: -1px;
}}
QTabBar::tab {{
    background: transparent;
    color: {Colors.TEXT_MUTED};
    padding: 9px 18px;
    border: none;
    font-size: 13px;
    font-weight: 500;
    margin-right: 2px;
    border-bottom: 2px solid transparent;
}}
QTabBar::tab:selected {{
    color: {Colors.ACCENT};
    border-bottom: 2px solid {Colors.ACCENT};
    font-weight: 600;
}}
QTabBar::tab:hover:!selected {{
    color: {Colors.TEXT_PRIMARY};
    background: {Colors.BG_HOVER};
    border-radius: 6px 6px 0 0;
}}

/* ── Tables ── */
QTableWidget {{
    background-color: {Colors.BG_CARD};
    border: 1px solid {Colors.BORDER};
    border-radius: 8px;
    gridline-color: {Colors.BORDER};
    outline: none;
    color: {Colors.TEXT_PRIMARY};
    alternate-background-color: {Colors.BG_ROW_ALT};
}}
QTableWidget::item {{
    padding: 7px 10px;
    border: none;
    color: {Colors.TEXT_PRIMARY};
}}
QTableWidget::item:selected {{
    background-color: {Colors.ACCENT_LIGHT};
    color: {Colors.TEXT_PRIMARY};
}}
QHeaderView::section {{
    background-color: {Colors.BG_SIDEBAR};
    color: {Colors.TEXT_MUTED};
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.8px;
    text-transform: uppercase;
    padding: 9px 10px;
    border: none;
    border-bottom: 1px solid {Colors.BORDER};
    border-right: 1px solid {Colors.BORDER};
}}
QHeaderView::section:last {{
    border-right: none;
}}

/* ── Log output ── */
QTextEdit#logOutput {{
    background-color: #0A1120;
    color: #64748B;
    border: none;
    border-radius: 8px;
    padding: 12px;
    font-family: "Cascadia Code", "Fira Code", "Consolas", monospace;
    font-size: 12px;
}}

/* ── Group boxes ── */
QGroupBox {{
    font-size: 11px;
    font-weight: 700;
    color: {Colors.TEXT_MUTED};
    border: 1px solid {Colors.BORDER};
    border-radius: 8px;
    margin-top: 10px;
    padding-top: 10px;
    background: {Colors.BG_CARD};
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 5px;
    color: {Colors.TEXT_MUTED};
    background: {Colors.BG_CARD};
}}

/* ── Progress bar ── */
QProgressBar {{
    background-color: {Colors.BG_SIDEBAR};
    border: none;
    border-radius: 3px;
    height: 5px;
    color: transparent;
}}
QProgressBar::chunk {{
    background-color: {Colors.ACCENT};
    border-radius: 3px;
}}

/* ── Scrollbars ── */
QScrollBar:vertical {{
    background: {Colors.BG_SIDEBAR};
    width: 7px;
    margin: 0;
    border-radius: 3px;
}}
QScrollBar::handle:vertical {{
    background: {Colors.BORDER};
    border-radius: 3px;
    min-height: 24px;
}}
QScrollBar::handle:vertical:hover {{
    background: {Colors.TEXT_MUTED};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal {{
    background: {Colors.BG_SIDEBAR};
    height: 7px;
    border-radius: 3px;
}}
QScrollBar::handle:horizontal {{
    background: {Colors.BORDER};
    border-radius: 3px;
    min-width: 24px;
}}
QScrollBar::handle:horizontal:hover {{
    background: {Colors.TEXT_MUTED};
}}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}

/* ── Status Bar ── */
QStatusBar {{
    background-color: {Colors.BG_SIDEBAR};
    color: {Colors.TEXT_MUTED};
    border-top: 1px solid {Colors.BORDER};
    font-size: 12px;
    padding: 3px 12px;
}}

/* ── Splitter ── */
QSplitter::handle {{
    background-color: {Colors.BORDER};
}}
QSplitter::handle:horizontal {{ width: 1px; }}
QSplitter::handle:vertical   {{ height: 1px; }}

/* ── Tooltip ── */
QToolTip {{
    background-color: {Colors.BG_CARD};
    color: {Colors.TEXT_PRIMARY};
    border: 1px solid {Colors.BORDER};
    border-radius: 5px;
    padding: 5px 9px;
    font-size: 12px;
}}
"""


# Scan Worker Thread

class ScanWorker(QThread):
    log_signal   = pyqtSignal(str, str)   # (message, level)
    vuln_signal  = pyqtSignal(dict)
    done_signal  = pyqtSignal(dict)
    progress_signal = pyqtSignal(int, int)  # (current, total)

    def __init__(self, config: dict):
        super().__init__()
        self.config  = config
        self._stop   = False
        self.results = {
            "target":           config["target"],
            "scan_start":       datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scan_end":         None,
            "endpoints_tested": 0,
            "params_tested":    0,
            "vulnerabilities":  [],
        }

    def stop(self):
        self._stop = True

    def run(self):
        try:
            self.log("ScanWorker.run() started", "info")

            # Import here so GUI loads fast even if backend modules have errors
            import requests
            from crawler import Crawler
            from scanner import SQLiScanner
            from reporter import Reporter

            self.log("Imports successful", "info")

            # Build a GUI-aware reporter
            reporter = GUIReporter(
                self.log_signal,
                self.vuln_signal,
                log_file=self.config.get("log_file")
            )
            reporter.verbose_mode = self.config.get("verbose", False)

            self.log("Reporter created", "info")
            self.log("Starting scan…", "info")
            self.log(f"Target: {self.config['target']}", "info")
            self.log(f"Methods: {', '.join(self.config.get('methods', []))}", "info")

            scanner = SQLiScanner(self.config, reporter, lambda: self._stop)
            self.log("Scanner created", "info")

            # Run the scan (blocking)
            self.log("Calling scanner.run()", "info")
            scanner.run()
            self.log("scanner.run() completed", "info")

            self.results = scanner.results
            self.results["scan_end"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            self.log("", "spacer")
            count = len(self.results["vulnerabilities"])
            self.log(f"Final results: {count} vulnerabilities found", "info")
            if count:
                self.log(f"Scan complete - {count} vulnerabilit{'y' if count==1 else 'ies'} found.", "success")
            else:
                self.log("Scan complete - no vulnerabilities found.", "success")

        except ImportError as e:
            self.log(f"Import error: {e}", "error")
            self.log("Make sure all backend files are in the same folder.", "error")
        except Exception as e:
            self.log(f"Scan error: {e}", "error")
            import traceback
            self.log(traceback.format_exc(), "error")
        finally:
            self.log("ScanWorker.run() finished, emitting done_signal", "info")
            self.done_signal.emit(self.results)

    def log(self, msg, level="info"):
        self.log_signal.emit(msg, level)


class GUIReporter:
    """Bridges scanner.py's Reporter interface to Qt signals."""
    def __init__(self, log_signal, vuln_signal, log_file: str = None):
        self.log_signal  = log_signal
        self.vuln_signal = vuln_signal
        self.verbose_mode = False
        self.log_file = log_file
        self._vuln_count = 0

        if self.log_file:
            self._write_log("INFO", f"Creating GUI scan log: {self.log_file}")

    def _write_log(self, level: str, msg: str):
        if not self.log_file:
            return
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(f"{timestamp} [{level}] {msg}\n")
        except Exception:
            pass

    def info(self, msg):
        self.log_signal.emit(str(msg), "info")
        self._write_log("INFO", str(msg))

    def success(self, msg):
        self.log_signal.emit(str(msg), "success")
        self._write_log("INFO", str(msg))

    def warning(self, msg):
        self.log_signal.emit(str(msg), "warning")
        self._write_log("WARNING", str(msg))

    def error(self, msg):
        self.log_signal.emit(str(msg), "error")
        self._write_log("ERROR", str(msg))

    def verbose(self, msg):
        self._write_log("DEBUG", str(msg))
        if self.verbose_mode:
            self.log_signal.emit(str(msg), "verbose")

    def section(self, title):
        self.log_signal.emit(f"── {title} ──", "section")
        self._write_log("INFO", f"SECTION: {title}")

    def vulnerability(self, vuln: dict):
        self._vuln_count += 1
        self.vuln_signal.emit(vuln)
        detail = (
            f"[{vuln.get('severity','?')}] {vuln.get('injection_type')} on "
            f"{vuln.get('parameter')} @ {vuln.get('url')}"
        )
        self.log_signal.emit(detail, "vuln")
        self._write_log("WARNING", detail)
        if vuln.get("extracted_data"):
            for k, v in vuln["extracted_data"].items():
                self._write_log("WARNING", f"Extracted {k}: {v}")

    def summary(self, results): pass   # GUI handles this

    def save_to_file(self, results, path):
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, default=str)
            self._write_log("INFO", f"Results exported → {path}")
        except Exception as e:
            self.log_signal.emit(f"Could not save: {e}", "error")
            self._write_log("ERROR", f"Could not save results: {e}")


# Stat Card Widget

class StatCard(QFrame):
    def __init__(self, label: str, value: str = "-", color: str = Colors.ACCENT):
        super().__init__()
        self.color = color
        self.setObjectName("statCard")
        self.setStyleSheet(f"""
            #statCard {{
                background: {Colors.BG_CARD};
                border: 1px solid {Colors.BORDER};
                border-radius: 8px;
                padding: 4px;
            }}
        """)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(4)

        self.value_label = QLabel(value)
        self.value_label.setStyleSheet(f"font-size: 26px; font-weight: 700; color: {color};")
        self.value_label.setAlignment(Qt.AlignLeft)

        self.text_label = QLabel(label)
        self.text_label.setStyleSheet(f"font-size: 12px; color: {Colors.TEXT_SECONDARY}; font-weight: 500;")

        layout.addWidget(self.value_label)
        layout.addWidget(self.text_label)

    def set_value(self, v: str):
        self.value_label.setText(str(v))


# Severity Badge Widget

class SeverityBadge(QLabel):
    def __init__(self, severity: str):
        super().__init__(severity)
        fg = SEVERITY_FG.get(severity, Colors.TEXT_SECONDARY)
        bg = SEVERITY_BG.get(severity, Colors.BG_SECONDARY)
        self.setStyleSheet(f"""
            background-color: {bg};
            color: {fg};
            border-radius: 6px;
            padding: 3px 10px;
            font-size: 11px;
            font-weight: 700;
        """)
        self.setAlignment(Qt.AlignCenter)
        self.setFixedHeight(24)


# Log Output with colored lines

class LogWidget(QTextEdit):
    LOG_COLORS = {
        "info":    "#94A3B8",
        "success": "#34D399",
        "warning": "#FBBF24",
        "error":   "#F87171",
        "verbose": "#64748B",
        "section": "#60A5FA",
        "vuln":    "#F472B6",
        "spacer":  "#1E293B",
    }
    LOG_PREFIXES = {
        "info":    "  ·  ",
        "success": "  OK  ",
        "warning": "  [!]  ",
        "error":   "  FAIL  ",
        "verbose": "  ~  ",
        "section": "\n  ━  ",
        "vuln":    "  [!]  ",
        "spacer":  "",
    }

    def __init__(self):
        super().__init__()
        self.setObjectName("logOutput")
        self.setReadOnly(True)
        self.setLineWrapMode(QTextEdit.WidgetWidth)

    def append_log(self, message: str, level: str = "info"):
        color  = self.LOG_COLORS.get(level, "#94A3B8")
        prefix = self.LOG_PREFIXES.get(level, "  ·  ")
        ts     = datetime.now().strftime("%H:%M:%S")

        if level == "spacer":
            html = f'<span style="color:#1E293B;">{"─" * 40}</span>'
        elif level == "section":
            html = (
                f'<br>'
                f'<span style="color:#60A5FA; font-weight:600;">'
                f'{prefix}{message}'
                f'</span><br>'
            )
        else:
            html = (
                f'<span style="color:#334155;">[{ts}]</span> '
                f'<span style="color:{color};">'
                f'{prefix}{message}'
                f'</span>'
            )

        self.append(html)
        # Auto-scroll
        sb = self.verticalScrollBar()
        sb.setValue(sb.maximum())

    def clear_log(self):
        self.clear()


# Vulnerability Detail Panel

class VulnDetailPanel(QFrame):
    def __init__(self):
        super().__init__()
        self.setStyleSheet(f"""
            QFrame {{
                background: {Colors.BG_CARD};
                border-left: 1px solid {Colors.BORDER};
            }}
        """)
        self.setMinimumWidth(320)
        self.setMaximumWidth(440)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        title = QLabel("Vulnerability Detail")
        title.setStyleSheet(f"font-size: 14px; font-weight: 700; color: {Colors.TEXT_PRIMARY};")
        layout.addWidget(title)

        self.placeholder = QLabel("Select a vulnerability\nfrom the table to view details.")
        self.placeholder.setStyleSheet(f"color: {Colors.TEXT_MUTED}; font-size: 12px;")
        self.placeholder.setAlignment(Qt.AlignCenter)
        self.placeholder.setWordWrap(True)

        self.detail_scroll = QScrollArea()
        self.detail_scroll.setWidgetResizable(True)
        self.detail_scroll.setFrameShape(QFrame.NoFrame)
        self.detail_widget = QWidget()
        self.detail_layout = QVBoxLayout(self.detail_widget)
        self.detail_layout.setSpacing(8)
        self.detail_layout.setContentsMargins(0, 0, 0, 0)
        self.detail_scroll.setWidget(self.detail_widget)

        layout.addWidget(self.placeholder)
        layout.addWidget(self.detail_scroll)
        layout.addStretch()

        self.detail_scroll.hide()

    def show_vuln(self, vuln: dict):
        self.placeholder.hide()
        self.detail_scroll.show()

        # Clear
        while self.detail_layout.count():
            item = self.detail_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        sev = vuln.get("severity", "INFO")
        badge = SeverityBadge(sev)
        self.detail_layout.addWidget(badge)

        fields = [
            ("Type",      vuln.get("injection_type", "?")),
            ("URL",       vuln.get("url", "?")),
            ("Parameter", vuln.get("parameter", "?")),
            ("Method",    vuln.get("method", "?")),
            ("Detected",  vuln.get("timestamp", "?")),
        ]
        for label, value in fields:
            self._add_field(label, str(value))

        # Payload box
        payload_title = QLabel("Payload")
        payload_title.setStyleSheet(f"font-size: 11px; font-weight: 700; color: {Colors.TEXT_MUTED}; text-transform: uppercase; letter-spacing: 0.5px;")
        payload_box = QTextEdit()
        payload_box.setReadOnly(True)
        payload_box.setPlainText(vuln.get("payload", ""))
        payload_box.setStyleSheet(f"""
            background: #0F172A;
            color: #34D399;
            border-radius: 8px;
            padding: 10px;
            font-family: "Cascadia Code", "Fira Code", Consolas, monospace;
            font-size: 11px;
        """)
        payload_box.setMaximumHeight(90)
        self.detail_layout.addWidget(payload_title)
        self.detail_layout.addWidget(payload_box)

        detail = vuln.get("detail", "")
        if detail:
            self._add_field("Analysis", detail, wrap=True)

        extracted = vuln.get("extracted_data")
        if extracted:
            ext_title = QLabel("Extracted Data")
            ext_title.setStyleSheet(f"font-size: 11px; font-weight: 700; color: {Colors.DANGER}; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 8px;")
            self.detail_layout.addWidget(ext_title)
            for k, v in extracted.items():
                self._add_field(k, str(v)[:400], wrap=True)

        self.detail_layout.addStretch()

    def _add_field(self, label: str, value: str, wrap: bool = False):
        lbl = QLabel(label)
        lbl.setStyleSheet(f"font-size: 11px; font-weight: 700; color: {Colors.TEXT_MUTED}; text-transform: uppercase; letter-spacing: 0.5px;")
        val = QLabel(value)
        val.setStyleSheet(f"font-size: 12px; color: {Colors.TEXT_PRIMARY}; padding: 2px 0;")
        if wrap:
            val.setWordWrap(True)
        else:
            val.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.detail_layout.addWidget(lbl)
        self.detail_layout.addWidget(val)


# Main Window

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SQLi Scout")
        self.setMinimumSize(1200, 760)
        self.resize(1380, 840)
        self.setStyleSheet(STYLESHEET)

        self._worker = None
        self._vulns  = []
        self._scan_start = None

        # Timer for elapsed display
        self._elapsed_timer = QTimer()
        self._elapsed_timer.timeout.connect(self._update_elapsed)

        self._build_ui()
        self._update_stats(0, 0, 0, 0)

    # UI Construction

    def _build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # Left sidebar
        sidebar = self._build_sidebar()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(270)

        # Right content
        content = self._build_content()

        root_layout.addWidget(sidebar)
        root_layout.addWidget(content, 1)

        # Status bar
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self._status_label = QLabel("Ready")
        self._elapsed_label = QLabel("")
        self.statusBar.addWidget(self._status_label)
        self.statusBar.addPermanentWidget(self._elapsed_label)

    # Sidebar

    def _build_sidebar(self) -> QWidget:
        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(20, 24, 20, 20)
        layout.setSpacing(0)

        # Logo / title
        logo_row = QHBoxLayout()
        dot = QLabel("•")
        dot.setStyleSheet(f"color: {Colors.ACCENT}; font-size: 20px;")
        app_title = QLabel("SQLi Scout")
        app_title.setObjectName("appTitle")
        logo_row.addWidget(dot)
        logo_row.addWidget(app_title)
        logo_row.addStretch()
        layout.addLayout(logo_row)

        sub = QLabel("SQL Injection Scanner")
        sub.setObjectName("appSubtitle")
        sub.setContentsMargins(28, 2, 0, 0)
        layout.addWidget(sub)
        layout.addSpacing(28)

        # Target
        self._add_sidebar_section(layout, "TARGET")

        url_label = QLabel("URL")
        url_label.setStyleSheet(f"color: {Colors.TEXT_SIDEBAR}; font-size: 12px; margin-bottom: 4px;")
        layout.addWidget(url_label)

        self.url_input = QLineEdit("http://localhost:3000")
        self.url_input.setObjectName("urlInput")
        self.url_input.setPlaceholderText("http://target.com")
        self.url_input.setStyleSheet(f"""
            QLineEdit {{
                background: #2A3A4E;
                border: 1.5px solid #334155;
                border-radius: 8px;
                color: #E2E8F0;
                padding: 9px 12px;
                font-size: 13px;
            }}
            QLineEdit:focus {{
                border-color: {Colors.ACCENT};
            }}
        """)
        layout.addWidget(self.url_input)
        layout.addSpacing(16)

        # Detection Methods
        self._add_sidebar_section(layout, "DETECTION METHODS")

        self.method_checks = {}
        methods = [
            ("error",   "Error-Based",        "Triggers visible DB errors"),
            ("boolean", "Boolean-Based Blind", "True/false response diff"),
            ("time",    "Time-Based Blind",    "Measures DB delays"),
            ("union",   "Union-Based",         "Extracts real data"),
        ]
        for key, label, tip in methods:
            cb = QCheckBox(label)
            cb.setChecked(True)
            cb.setToolTip(tip)
            layout.addWidget(cb)
            self.method_checks[key] = cb
        layout.addSpacing(16)

        # Options
        self._add_sidebar_section(layout, "OPTIONS")

        options_grid = QWidget()
        options_grid.setStyleSheet("background: transparent;")
        grid = QVBoxLayout(options_grid)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setSpacing(8)

        self.threads_spin  = self._sidebar_spinbox("Threads", 1, 20, 5)
        self.timeout_spin  = self._sidebar_spinbox("Timeout (s)", 3, 60, 10)
        self.depth_spin    = self._sidebar_spinbox("Crawl Depth", 0, 5, 2)
        self.delay_dspin   = self._sidebar_dspinbox("Request Delay (s)", 0.0, 10.0, 0.0)
        self.time_thresh   = self._sidebar_dspinbox("Time Threshold (s)", 1.0, 30.0, 4.0)

        for w in [self.threads_spin, self.timeout_spin, self.depth_spin,
                  self.delay_dspin, self.time_thresh]:
            grid.addWidget(w)

        layout.addWidget(options_grid)
        layout.addSpacing(10)

        # Checkboxes
        self.waf_check = QCheckBox("WAF Evasion")
        self.waf_check.setChecked(True)
        self.verbose_check = QCheckBox("Verbose Logging")
        self.verbose_check.setChecked(True)  # Enable verbose by default for debugging
        layout.addWidget(self.waf_check)
        layout.addWidget(self.verbose_check)
        layout.addSpacing(16)

        # Auth / Headers
        self._add_sidebar_section(layout, "AUTH / HEADERS")

        cookie_label = QLabel("Cookies")
        cookie_label.setStyleSheet(f"color: {Colors.TEXT_SIDEBAR}; font-size: 12px;")
        layout.addWidget(cookie_label)
        self.cookies_input = QLineEdit()
        self.cookies_input.setPlaceholderText("session=abc; token=xyz")
        self.cookies_input.setStyleSheet(f"""
            QLineEdit {{
                background: #2A3A4E;
                border: 1.5px solid #334155;
                border-radius: 8px;
                color: #E2E8F0;
                padding: 7px 10px;
                font-size: 12px;
            }}
            QLineEdit:focus {{ border-color: {Colors.ACCENT}; }}
        """)
        layout.addWidget(self.cookies_input)

        header_label = QLabel("Custom Header")
        header_label.setStyleSheet(f"color: {Colors.TEXT_SIDEBAR}; font-size: 12px; margin-top: 6px;")
        layout.addWidget(header_label)
        self.header_input = QLineEdit()
        self.header_input.setPlaceholderText("Authorization: Bearer <token>")
        self.header_input.setStyleSheet(f"""
            QLineEdit {{
                background: #2A3A4E;
                border: 1.5px solid #334155;
                border-radius: 8px;
                color: #E2E8F0;
                padding: 7px 10px;
                font-size: 12px;
            }}
            QLineEdit:focus {{ border-color: {Colors.ACCENT}; }}
        """)
        layout.addWidget(self.header_input)

        layout.addStretch()

        # Action buttons
        # Separator label above deep scan
        sep_line = QFrame()
        sep_line.setFixedHeight(1)
        sep_line.setStyleSheet(f"background: {Colors.BORDER};")
        layout.addWidget(sep_line)

        scan_lbl = QLabel("Full scan with all 4 detection methods.")
        scan_lbl.setStyleSheet(f"font-size: 10px; color: {Colors.TEXT_MUTED}; background: transparent;")
        scan_lbl.setWordWrap(True)
        layout.addWidget(scan_lbl)

        self.scan_btn = QPushButton("Deep Scan")
        self.scan_btn.setObjectName("primaryBtn")
        self.scan_btn.clicked.connect(self._start_scan)
        self.scan_btn.setCursor(Qt.PointingHandCursor)

        self.stop_btn = QPushButton("Stop Scan")
        self.stop_btn.setObjectName("dangerBtn")
        self.stop_btn.clicked.connect(self._stop_scan)
        self.stop_btn.setCursor(Qt.PointingHandCursor)
        self.stop_btn.hide()

        layout.addWidget(self.scan_btn)
        layout.addWidget(self.stop_btn)
        layout.addSpacing(4)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)  # Indeterminate
        self.progress_bar.hide()
        layout.addWidget(self.progress_bar)

        return sidebar

    def _add_sidebar_section(self, layout: QVBoxLayout, text: str):
        lbl = QLabel(text)
        lbl.setObjectName("sidebarSection")
        layout.addWidget(lbl)
        layout.addSpacing(4)

    def _sidebar_spinbox(self, label: str, min_: int, max_: int, default: int) -> QWidget:
        w = QWidget()
        w.setStyleSheet("background: transparent;")
        row = QHBoxLayout(w)
        row.setContentsMargins(0, 0, 0, 0)
        lbl = QLabel(label)
        lbl.setStyleSheet(f"color: {Colors.TEXT_SIDEBAR}; font-size: 12px;")
        spin = QSpinBox()
        spin.setRange(min_, max_)
        spin.setValue(default)
        spin.setFixedWidth(70)
        spin.setStyleSheet(f"""
            QSpinBox {{
                background: #2A3A4E;
                border: 1.5px solid #334155;
                border-radius: 6px;
                color: #E2E8F0;
                padding: 4px 8px;
                font-size: 12px;
            }}
            QSpinBox:focus {{ border-color: {Colors.ACCENT}; }}
            QSpinBox::up-button, QSpinBox::down-button {{ width: 16px; }}
        """)
        row.addWidget(lbl)
        row.addStretch()
        row.addWidget(spin)
        # Store spin as attribute on the wrapper widget for easy access
        w._spin = spin
        return w

    def _sidebar_dspinbox(self, label: str, min_: float, max_: float, default: float) -> QWidget:
        w = QWidget()
        w.setStyleSheet("background: transparent;")
        row = QHBoxLayout(w)
        row.setContentsMargins(0, 0, 0, 0)
        lbl = QLabel(label)
        lbl.setStyleSheet(f"color: {Colors.TEXT_SIDEBAR}; font-size: 12px;")
        spin = QDoubleSpinBox()
        spin.setRange(min_, max_)
        spin.setValue(default)
        spin.setSingleStep(0.5)
        spin.setFixedWidth(70)
        spin.setStyleSheet(f"""
            QDoubleSpinBox {{
                background: #2A3A4E;
                border: 1.5px solid #334155;
                border-radius: 6px;
                color: #E2E8F0;
                padding: 4px 8px;
                font-size: 12px;
            }}
            QDoubleSpinBox:focus {{ border-color: {Colors.ACCENT}; }}
            QDoubleSpinBox::up-button, QDoubleSpinBox::down-button {{ width: 16px; }}
        """)
        row.addWidget(lbl)
        row.addStretch()
        row.addWidget(spin)
        w._spin = spin
        return w

    # Content area

    def _build_content(self) -> QWidget:
        content = QWidget()
        content.setStyleSheet(f"background: {Colors.BG_CONTENT};")
        layout = QVBoxLayout(content)
        layout.setContentsMargins(24, 24, 24, 16)
        layout.setSpacing(16)

        # Stats row
        stats_row = QHBoxLayout()
        stats_row.setSpacing(12)
        self.card_vulns     = StatCard("Vulnerabilities",    "-", Colors.DANGER)
        self.card_critical  = StatCard("Critical / High",    "-", Colors.SEV_CRITICAL)
        self.card_endpoints = StatCard("Endpoints Tested",   "-", Colors.ACCENT)
        self.card_params    = StatCard("Parameters Tested",  "-", Colors.SUCCESS)
        for card in [self.card_vulns, self.card_critical,
                     self.card_endpoints, self.card_params]:
            stats_row.addWidget(card)
        layout.addLayout(stats_row)

        # Tabs
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)

        # Tab 0: Quick Launch
        if HAS_QUICK_LAUNCH:
            self.quick_launch = QuickLaunchTab()
            self.tabs.addTab(self.quick_launch, "  Quick Launch  ")

        # Tab 1: Vulnerabilities
        vuln_tab = self._build_vuln_tab()
        self.tabs.addTab(vuln_tab, "  Vulnerabilities  ")

        # Tab 2: Scan Log
        log_tab = self._build_log_tab()
        self.tabs.addTab(log_tab, "  Scan Log  ")

        # Tab 3: Extracted Data
        data_tab = self._build_data_tab()
        self.tabs.addTab(data_tab, "  Extracted Data  ")

        # Tab 4: Payload Lab
        if HAS_PAYLOAD_LAB:
            self.payload_lab = PayloadLabTab()
            self.tabs.addTab(self.payload_lab, "  Payload Lab  ")

        layout.addWidget(self.tabs)
        return content

    def _build_vuln_tab(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet(f"background: {Colors.BG_CONTENT};")
        layout = QHBoxLayout(w)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(16, 16, 16, 16)
        left_layout.setSpacing(12)

        # Toolbar
        toolbar = QHBoxLayout()
        filter_label = QLabel("Filter:")
        filter_label.setStyleSheet(f"color: {Colors.TEXT_SECONDARY}; font-size: 12px;")
        self.sev_filter = QComboBox()
        self.sev_filter.addItems(["All Severities", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
        self.sev_filter.setFixedWidth(160)
        self.sev_filter.currentTextChanged.connect(self._filter_vulns)

        clear_btn = QPushButton("Clear All")
        clear_btn.setObjectName("iconBtn")
        clear_btn.setCursor(Qt.PointingHandCursor)
        clear_btn.clicked.connect(self._clear_vulns)

        export_btn = QPushButton("Export JSON")
        export_btn.setObjectName("iconBtn")
        export_btn.setCursor(Qt.PointingHandCursor)
        export_btn.clicked.connect(self._export_results)

        toolbar.addWidget(filter_label)
        toolbar.addWidget(self.sev_filter)
        toolbar.addStretch()
        toolbar.addWidget(clear_btn)
        toolbar.addWidget(export_btn)
        left_layout.addLayout(toolbar)

        # Vuln table
        self.vuln_table = QTableWidget()
        self.vuln_table.setObjectName("vulnTable")
        self.vuln_table.setColumnCount(5)
        self.vuln_table.setHorizontalHeaderLabels(["Severity", "Type", "Parameter", "URL", "Time"])
        self.vuln_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.vuln_table.horizontalHeader().setDefaultSectionSize(130)
        self.vuln_table.setColumnWidth(0, 100)
        self.vuln_table.setColumnWidth(1, 190)
        self.vuln_table.setColumnWidth(2, 120)
        self.vuln_table.setColumnWidth(4, 90)
        self.vuln_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.vuln_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.vuln_table.setAlternatingRowColors(False)
        self.vuln_table.verticalHeader().setVisible(False)
        self.vuln_table.setShowGrid(False)
        self.vuln_table.setFocusPolicy(Qt.NoFocus)
        self.vuln_table.itemSelectionChanged.connect(self._on_vuln_selected)
        self.vuln_table.setRowCount(0)

        left_layout.addWidget(self.vuln_table)

        # Detail panel
        self.detail_panel = VulnDetailPanel()

        layout.addWidget(left, 1)
        layout.addWidget(self.detail_panel)
        return w

    def _build_log_tab(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet(f"background: {Colors.BG_CONTENT};")
        layout = QVBoxLayout(w)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Log toolbar
        log_toolbar = QHBoxLayout()
        log_title = QLabel("Scan Output")
        log_title.setStyleSheet(f"font-weight: 600; font-size: 14px; color: {Colors.TEXT_PRIMARY};")

        clear_log_btn = QPushButton("Clear Log")
        clear_log_btn.setObjectName("iconBtn")
        clear_log_btn.setCursor(Qt.PointingHandCursor)
        clear_log_btn.clicked.connect(lambda: self.log_widget.clear_log())

        log_toolbar.addWidget(log_title)
        log_toolbar.addStretch()
        log_toolbar.addWidget(clear_log_btn)

        export_log_btn = QPushButton("Export Log")
        export_log_btn.setObjectName("iconBtn")
        export_log_btn.setCursor(Qt.PointingHandCursor)
        export_log_btn.clicked.connect(self._export_log)
        log_toolbar.addWidget(export_log_btn)

        layout.addLayout(log_toolbar)

        self.log_widget = LogWidget()
        layout.addWidget(self.log_widget)
        return w

    def _build_data_tab(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet(f"background: {Colors.BG_CONTENT};")
        layout = QVBoxLayout(w)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        header = QHBoxLayout()
        title = QLabel("Extracted Data")
        title.setStyleSheet(f"font-weight: 600; font-size: 14px; color: {Colors.TEXT_PRIMARY};")
        self.copy_data_btn = QPushButton("Copy All")
        self.copy_data_btn.setObjectName("iconBtn")
        self.copy_data_btn.setCursor(Qt.PointingHandCursor)
        self.copy_data_btn.clicked.connect(self._copy_extracted)
        header.addWidget(title)
        header.addStretch()
        header.addWidget(self.copy_data_btn)
        layout.addLayout(header)

        self.data_table = QTableWidget()
        self.data_table.setColumnCount(3)
        self.data_table.setHorizontalHeaderLabels(["Source", "Key", "Value"])
        self.data_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.data_table.setColumnWidth(0, 200)
        self.data_table.setColumnWidth(1, 180)
        self.data_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.data_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.data_table.verticalHeader().setVisible(False)
        self.data_table.setShowGrid(False)
        self.data_table.setAlternatingRowColors(True)
        layout.addWidget(self.data_table)
        return w

    # Scan control

    def _build_config(self) -> dict:
        url = self.url_input.text().strip()
        if not url:
            return None

        # Check if URL has query parameters
        from urllib.parse import urlparse
        parsed = urlparse(url)
        has_params = bool(parsed.query)

        methods = [k for k, cb in self.method_checks.items() if cb.isChecked()]
        if not methods:
            return None

        headers = {}
        raw_header = self.header_input.text().strip()
        if raw_header and ":" in raw_header:
            k, v = raw_header.split(":", 1)
            headers[k.strip()] = v.strip()

        cookies = {}
        raw_cookies = self.cookies_input.text().strip()
        if raw_cookies:
            for pair in raw_cookies.split(";"):
                pair = pair.strip()
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    cookies[k.strip()] = v.strip()

        config = {
            "target":         url,
            "methods":        methods,
            "threads":        self.threads_spin._spin.value(),
            "timeout":        self.timeout_spin._spin.value(),
            "crawl_depth":    self.depth_spin._spin.value(),
            "max_crawl_pages": 200,
            "max_endpoints":   300,
            "delay":          self.delay_dspin._spin.value(),
            "time_threshold": self.time_thresh._spin.value(),
            "waf_evasion":    self.waf_check.isChecked(),
            "verbose":        self.verbose_check.isChecked(),
            "headers":        headers,
            "cookies":        cookies,
            "no_crawl":       False,
            "output":         None,
        }

        # Warn if no query parameters
        if not has_params:
            self.log_widget.append_log(f"Warning: URL '{url}' has no query parameters. The scanner will try common parameter names.", "warning")

        return config

    def _start_scan(self):
        config = self._build_config()
        if not config:
            QMessageBox.warning(self, "Missing Input",
                                "Please enter a target URL and select at least one detection method.")
            return

        # Debug: Log the configuration
        self.log_widget.append_log(f"Config: {json.dumps(config, indent=2)}", "info")

        # Reset state
        self._vulns = []
        self.vuln_table.setRowCount(0)
        self.data_table.setRowCount(0)
        self.log_widget.clear_log()
        self._update_stats(0, 0, 0, 0)
        self.tabs.setCurrentIndex(1)  # Switch to log tab

        # UI state
        self.scan_btn.hide()
        self.stop_btn.show()
        self.progress_bar.show()
        self._set_inputs_enabled(False)

        self._scan_start = time.time()
        self._elapsed_timer.start(1000)
        self._set_status("Scanning…", Colors.ACCENT)

        # Worker
        try:
            self._worker = ScanWorker(config)
            self._worker.log_signal.connect(self._on_log)
            self._worker.vuln_signal.connect(self._on_vuln)
            self._worker.done_signal.connect(self._on_done)
            self._worker.start()
            self.log_widget.append_log("Scan worker started successfully", "info")
        except Exception as e:
            self.log_widget.append_log(f"Failed to start scan worker: {e}", "error")
            import traceback
            self.log_widget.append_log(traceback.format_exc(), "error")
            self._scan_finished()

    def _stop_scan(self):
        if self._worker:
            self._worker.stop()
            self._worker.terminate()
            self.log_widget.append_log("Scan stopped by user.", "warning")
        self._scan_finished()

    def _scan_finished(self):
        self.scan_btn.show()
        self.stop_btn.hide()
        self.progress_bar.hide()
        self._set_inputs_enabled(True)
        self._elapsed_timer.stop()

    # Signals

    def _on_log(self, message: str, level: str):
        self.log_widget.append_log(message, level)

    def _on_vuln(self, vuln: dict):
        self._vulns.append(vuln)
        self._add_vuln_row(vuln)

        # Add extracted data
        if vuln.get("extracted_data"):
            src = f"{vuln.get('injection_type')} / {vuln.get('parameter')}"
            for k, v in vuln["extracted_data"].items():
                row = self.data_table.rowCount()
                self.data_table.insertRow(row)
                self.data_table.setItem(row, 0, QTableWidgetItem(src))
                self.data_table.setItem(row, 1, QTableWidgetItem(k))
                self.data_table.setItem(row, 2, QTableWidgetItem(str(v)))

        # Update stats
        total   = len(self._vulns)
        hi_crit = sum(1 for v in self._vulns if v.get("severity") in ("CRITICAL", "HIGH"))
        self._update_stats(total, hi_crit, None, None)

        # Flash tab badge
        self.tabs.setTabText(0, f"  Vulnerabilities ({total})  ")

    def _on_done(self, results: dict):
        self.log_widget.append_log(f"_on_done called with results: {len(results.get('vulnerabilities', []))} vulns", "info")
        self._scan_finished()
        ep  = results.get("endpoints_tested", 0)
        prm = results.get("params_tested",    0)
        n   = len(results.get("vulnerabilities", []))
        hi  = sum(1 for v in results.get("vulnerabilities", [])
                  if v.get("severity") in ("CRITICAL", "HIGH"))
        self._update_stats(n, hi, ep, prm)

        if n:
            self._set_status(f"Scan complete - {n} vulnerabilit{'y' if n==1 else 'ies'} found", Colors.DANGER)
            self.tabs.setCurrentIndex(0)  # Switch to vulns tab
        else:
            self._set_status("Scan complete - no vulnerabilities found", Colors.SUCCESS)

        self._last_results = results

    # Table helpers

    def _add_vuln_row(self, vuln: dict, apply_filter: bool = True):
        sev = vuln.get("severity", "INFO")

        # Apply current filter
        if apply_filter:
            current_filter = self.sev_filter.currentText()
            if current_filter != "All Severities" and current_filter != sev:
                return

        row = self.vuln_table.rowCount()
        self.vuln_table.insertRow(row)
        self.vuln_table.setRowHeight(row, 44)

        # Severity badge cell
        badge_widget = QWidget()
        badge_layout = QHBoxLayout(badge_widget)
        badge_layout.setContentsMargins(8, 4, 8, 4)
        badge = SeverityBadge(sev)
        badge_layout.addWidget(badge)
        badge_layout.addStretch()
        self.vuln_table.setCellWidget(row, 0, badge_widget)

        def make_item(text: str) -> QTableWidgetItem:
            item = QTableWidgetItem(text)
            item.setForeground(QColor(Colors.TEXT_PRIMARY))
            return item

        self.vuln_table.setItem(row, 1, make_item(vuln.get("injection_type", "")))
        self.vuln_table.setItem(row, 2, make_item(vuln.get("parameter", "")))
        self.vuln_table.setItem(row, 3, make_item(vuln.get("url", "")))
        ts = vuln.get("timestamp", "")[-8:] if vuln.get("timestamp") else ""
        self.vuln_table.setItem(row, 4, make_item(ts))

        # Store vuln index in first real item
        self.vuln_table.item(row, 1).setData(Qt.UserRole, len(self._vulns) - 1)

    def _on_vuln_selected(self):
        rows = self.vuln_table.selectedItems()
        if not rows:
            return
        # Find the row index
        row = self.vuln_table.currentRow()
        type_item = self.vuln_table.item(row, 1)
        if type_item:
            idx = type_item.data(Qt.UserRole)
            if idx is not None and 0 <= idx < len(self._vulns):
                self.detail_panel.show_vuln(self._vulns[idx])

    def _filter_vulns(self, filter_text: str):
        """Re-render table with current severity filter."""
        self.vuln_table.setRowCount(0)
        for vuln in self._vulns:
            self._add_vuln_row(vuln, apply_filter=True)

    def _clear_vulns(self):
        self._vulns = []
        self.vuln_table.setRowCount(0)
        self.data_table.setRowCount(0)
        self.tabs.setTabText(0, "  Vulnerabilities  ")
        self._update_stats(0, 0, None, None)

    # Export

    def _export_results(self):
        if not hasattr(self, "_last_results") or not self._last_results:
            if self._vulns:
                data = {"vulnerabilities": self._vulns}
            else:
                QMessageBox.information(self, "No Results", "Run a scan first.")
                return
        else:
            data = self._last_results

        path, _ = QFileDialog.getSaveFileName(
            self, "Save Results", "sqli_results.json",
            "JSON Files (*.json);;All Files (*)"
        )
        if path:
            try:
                with open(path, "w") as f:
                    json.dump(data, f, indent=2, default=str)
                self.log_widget.append_log(f"Results exported → {path}", "success")
                self._set_status(f"Exported to {path}", Colors.SUCCESS)
            except Exception as e:
                QMessageBox.critical(self, "Export Error", str(e))

    def _export_log(self):
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save scan log",
            "scan.log",
            "Log Files (*.log);;Text Files (*.txt);;All Files (*)"
        )
        if not path:
            return

        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.log_widget.toPlainText())
            self.log_widget.append_log(f"Log exported → {path}", "success")
            self._set_status(f"Log exported to {path}", Colors.SUCCESS)
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    def _copy_extracted(self):
        rows = []
        for r in range(self.data_table.rowCount()):
            src = self.data_table.item(r, 0)
            key = self.data_table.item(r, 1)
            val = self.data_table.item(r, 2)
            if src and key and val:
                rows.append(f"{src.text()} | {key.text()} | {val.text()}")
        QApplication.clipboard().setText("\n".join(rows))
        self._set_status("Copied to clipboard", Colors.SUCCESS)

    # Misc UI helpers

    def _update_stats(self, vulns, hi_crit, endpoints, params):
        if vulns is not None:    self.card_vulns.set_value(str(vulns))
        if hi_crit is not None:  self.card_critical.set_value(str(hi_crit))
        if endpoints is not None: self.card_endpoints.set_value(str(endpoints))
        if params is not None:   self.card_params.set_value(str(params))

    def _set_inputs_enabled(self, enabled: bool):
        self.url_input.setEnabled(enabled)
        self.cookies_input.setEnabled(enabled)
        self.header_input.setEnabled(enabled)
        for cb in self.method_checks.values():
            cb.setEnabled(enabled)
        for w in [self.threads_spin, self.timeout_spin, self.depth_spin,
                  self.delay_dspin, self.time_thresh]:
            w._spin.setEnabled(enabled)
        self.waf_check.setEnabled(enabled)
        self.verbose_check.setEnabled(enabled)

    def _set_status(self, msg: str, color: str = Colors.TEXT_SECONDARY):
        self._status_label.setText(msg)
        self._status_label.setStyleSheet(f"color: {color}; font-size: 12px;")

    def _update_elapsed(self):
        if self._scan_start:
            elapsed = int(time.time() - self._scan_start)
            m, s = divmod(elapsed, 60)
            self._elapsed_label.setText(f"Elapsed: {m:02d}:{s:02d}")

    def closeEvent(self, event):
        if self._worker and self._worker.isRunning():
            self._worker.terminate()
        event.accept()


# Entry point

def main():
    # High-DPI support (must be set before QApplication creation)
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setApplicationName("SQLi Scout")
    app.setOrganizationName("SQLiScout")

    # Font
    app.setFont(QFont("Segoe UI", 10))

    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()