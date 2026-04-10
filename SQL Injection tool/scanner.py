
# scanner.py - Core SQL Injection Detection Engine
# Detection methods implemented:
#   1. Error-Based: Trigger visible DB error messages
#   2. Boolean-Based: Infer injection via true/false response divergence
#   3. Time-Based Blind: Measure artificial DB delays
#   4. Union-Based: Extract real data once injection is confirmed

import time
import json
import threading
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs

from payloads import (
    ERROR_BASED, ERROR_SIGNATURES,
    BOOLEAN_BASED, get_time_payloads,
    union_order_by, union_null_probe, union_extract,
    UNION_EXTRACT_QUERIES, UNION_TABLE_SCHEMA,
    apply_waf_evasion,
)
from utils import (
    normalize_url, get_base_url,
    responses_differ_significantly, timed_call, truncate, safe_json_parse,
)
from crawler import Crawler
from reporter import Reporter


class SQLiScanner:
    def __init__(self, config: dict, reporter: Reporter, stop_flag=None):
        self.config   = config
        self.reporter = reporter
        self._lock    = threading.Lock()
        self._stop_flag = stop_flag  # Callable that returns True if scan should stop

        self.results = {
            "target":           config["target"],
            "scan_start":       time.strftime("%Y-%m-%d %H:%M:%S"),
            "scan_end":         None,
            "methods_used":     config.get("methods", []),
            "endpoints_tested": 0,
            "params_tested":    0,
            "log_file":         config.get("log_file"),
            "vulnerabilities":  [],
        }

        # Set of (url, param, method_name) already recorded - avoids duplicate rows
        self._recorded = set()

        # Build a shared requests.Session
        self.session = self._build_session()

    # Session setup

    def _build_session(self) -> requests.Session:
        s = requests.Session()
        s.headers.update({
            "User-Agent":      "Mozilla/5.0 (X11; Linux x86_64) SQLiScout/2.0 (Security Research)",
            "Accept":          "text/html,application/xhtml+xml,application/json,*/*;q=0.9",
            "Accept-Language": "en-US,en;q=0.9",
        })
        if self.config.get("headers"):
            s.headers.update(self.config["headers"])
        if self.config.get("cookies"):
            s.cookies.update(self.config["cookies"])
        return s

    def _should_stop(self):
        """Check if scan should be stopped."""
        return self._stop_flag and self._stop_flag()

    # Entry point

    def run(self):
        target = normalize_url(self.config["target"])
        self.reporter.info(f"Target    : {target}")
        self.reporter.info(f"Methods   : {', '.join(self.config.get('methods', []))}")
        self.reporter.info(f"Threads   : {self.config.get('threads', 5)}")
        self.reporter.info(f"WAF Evade : {self.config.get('waf_evasion', True)}")

        # Test basic connectivity
        try:
            self.reporter.info("Testing connectivity to target...")
            resp = self.session.get(target, timeout=self.config.get("timeout", 10))
            self.reporter.info(f"Target responds: HTTP {resp.status_code}")
        except Exception as e:
            self.reporter.error(f"Cannot connect to target: {e}")
            return

        # Discovery Phase
        self.reporter.section("DISCOVERY PHASE")

        if self.config.get("no_crawl"):
            endpoints = self._endpoints_from_single_url(target)
        else:
            crawler   = Crawler(self.config, self.session, self.reporter, self._stop_flag)
            endpoints = crawler.crawl()

        if not endpoints:
            self.reporter.warning("No endpoints discovered from crawling - falling back to testing the original URL.")
            endpoints = self._endpoints_from_single_url(target)

        if not endpoints:
            self.reporter.warning("No endpoints to test - aborting.")
            return

        self.reporter.info(f"Found {len(endpoints)} endpoint(s) to test")
        for ep in endpoints[:5]:  # Show first 5
            self.reporter.verbose(f"  Endpoint: {ep['method']} {ep['url']} params={list(ep.get('params', {}).keys())}")

        # Scanning Phase
        self.reporter.section("SCANNING PHASE")
        self.reporter.info(f"Testing {len(endpoints)} endpoint(s) with up to {self.config.get('threads',5)} thread(s)")

        with ThreadPoolExecutor(max_workers=self.config.get("threads", 5)) as pool:
            futures = {pool.submit(self._scan_endpoint, ep): ep for ep in endpoints}
            for future in as_completed(futures):
                if self._should_stop():
                    self.reporter.warning("Scan stopped by user")
                    break
                try:
                    future.result()
                except Exception as exc:
                    self.reporter.verbose(f"Thread error: {exc}")

        # Finalise Results
        self.results["scan_end"] = time.strftime("%Y-%m-%d %H:%M:%S")
        self.reporter.summary(self.results)

        output = self.config.get("output")
        if output:
            self.reporter.save_to_file(self.results, output)

    # Endpoint dispatch

    def _endpoints_from_single_url(self, url: str) -> list:
        parsed = urlparse(url)
        params = {k: v[0] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}
        return [{
            "url":    url.split("?")[0],
            "method": "GET",
            "params": params,
            "data":   None,
            "type":   "url_param",
        }]

    def _scan_endpoint(self, endpoint: dict):
        url    = endpoint["url"]
        method = endpoint["method"]
        params = dict(endpoint.get("params") or {})
        data   = dict(endpoint.get("data")   or {})

        with self._lock:
            self.results["endpoints_tested"] += 1

        # Build parameter list to inject into
        inject_targets = list(params.keys()) + list(data.keys())

        # If the endpoint has no explicit params, probe common generic names
        if not inject_targets:
            inject_targets = ["q", "search", "id", "name", "email",
                              "username", "query", "keyword", "term"]

        self.reporter.verbose(f"[{method}] {url}  params={inject_targets}")
        self.reporter.info(f"Testing endpoint: {method} {url} with {len(inject_targets)} parameter(s)")

        for param in inject_targets:
            if self._should_stop():
                self.reporter.warning("Scan stopped by user")
                return
            self.reporter.verbose(f"Testing parameter: {param}")
            with self._lock:
                self.results["params_tested"] += 1

            for method_name in self.config.get("methods", []):
                if self._should_stop():
                    self.reporter.warning("Scan stopped by user")
                    return
                self.reporter.verbose(f"Running {method_name} detection on {param}")
                if method_name == "error":
                    self._detect_error_based(endpoint, param)
                elif method_name == "boolean":
                    self._detect_boolean_based(endpoint, param)
                elif method_name == "time":
                    self._detect_time_based(endpoint, param)
                elif method_name == "union":
                    self._detect_union_based(endpoint, param)

            if self.config.get("delay"):
                time.sleep(self.config["delay"])

    # Error-Based Detection

    def _detect_error_based(self, endpoint: dict, param: str):
        self.reporter.verbose(f"Testing error-based injection on param '{param}'")
        payloads = list(ERROR_BASED)

        if self.config.get("waf_evasion"):
            # Add evasion variants for the first 6 base payloads (avoid payload explosion)
            evaded = []
            for p in payloads[:6]:
                evaded.extend(apply_waf_evasion(p))
            payloads = list(dict.fromkeys(payloads + evaded))  # ordered dedup

        self.reporter.verbose(f"Testing {len(payloads)} error-based payloads")
        for payload in payloads:
            try:
                resp = self._make_request(endpoint, param, payload)
                if resp is None:
                    self.reporter.verbose(f"  Request failed for payload: {payload}")
                    continue

                body_low = resp.text.lower()
                hit = next((sig for sig in ERROR_SIGNATURES if sig in body_low), None)

                if hit:
                    self.reporter.verbose(f"  Error signature detected: {hit}")
                    self._record(
                        endpoint, param, payload,
                        injection_type="Error-Based",
                        detail=f"DB error string detected: «{hit}»",
                        severity="HIGH",
                    )
                    return  # One confirmed hit is enough for this param

            except Exception as e:
                self.reporter.verbose(f"  error-based request failed: {e}")

    # Boolean-Based Blind Detection

    def _detect_boolean_based(self, endpoint: dict, param: str):
        # Baseline - a value that should return a neutral (non-error) response
        try:
            baseline_resp = self._make_request(endpoint, param, "neutralBaselineValue99")
            if baseline_resp is None:
                return
            baseline_body = baseline_resp.text
        except Exception:
            return

        for true_pl, false_pl in BOOLEAN_BASED:
            try:
                true_resp  = self._make_request(endpoint, param, true_pl)
                false_resp = self._make_request(endpoint, param, false_pl)

                if true_resp is None or false_resp is None:
                    continue

                injectable, stats = responses_differ_significantly(
                    true_resp.text, false_resp.text, baseline_body
                )

                if injectable:
                    detail = (
                        f"True/False response divergence detected | "
                        f"T-F sim={stats['true_false_sim']} | "
                        f"divergence={stats['divergence']}"
                    )
                    self._record(
                        endpoint, param, true_pl,
                        injection_type="Boolean-Based Blind",
                        detail=detail,
                        severity="HIGH",
                    )
                    return

            except Exception as e:
                self.reporter.verbose(f"  boolean request failed: {e}")

    # Time-Based Blind Detection

    def _detect_time_based(self, endpoint: dict, param: str):
        threshold = self.config.get("time_threshold", 4.0)
        sleep_sec = 5

        # Measure baseline latency (two samples for reliability)
        try:
            _, t1 = timed_call(self._make_request, endpoint, param, "baselineTimingA")
            _, t2 = timed_call(self._make_request, endpoint, param, "baselineTimingB")
            baseline_avg = (t1 + t2) / 2
        except Exception:
            return

        for payload, db_hint in get_time_payloads(seconds=sleep_sec):
            try:
                _, elapsed = timed_call(self._make_request, endpoint, param, payload)

                delay_triggered = (
                    elapsed >= threshold
                    and elapsed > baseline_avg + (sleep_sec * 0.6)
                )

                if delay_triggered:
                    detail = (
                        f"Response delayed {elapsed:.2f}s "
                        f"(baseline≈{baseline_avg:.2f}s, threshold={threshold}s) "
                        f"[DB hint: {db_hint}]"
                    )
                    self._record(
                        endpoint, param, payload,
                        injection_type="Time-Based Blind",
                        detail=detail,
                        severity="HIGH",
                    )
                    return

            except requests.exceptions.Timeout:
                # A timeout itself can confirm time-based injection
                detail = (
                    f"Request timed out after {self.config.get('timeout',10)}s "
                    f"- possible time-based injection [DB hint: {db_hint}]"
                )
                self._record(
                    endpoint, param, payload,
                    injection_type="Time-Based Blind",
                    detail=detail,
                    severity="MEDIUM",
                )
                return

            except Exception as e:
                self.reporter.verbose(f"  time-based request failed: {e}")

    # Union-Based Detection and Data Extraction

    def _detect_union_based(self, endpoint: dict, param: str):
        # Step 1 - Determine column count
        num_cols = self._find_column_count(endpoint, param)
        if num_cols is None or num_cols < 1:
            return

        self.reporter.verbose(f"  [UNION] {param} → {num_cols} column(s) detected")

        # Step 2 - Find a column whose content is reflected
        visible_col = self._find_visible_column(endpoint, param, num_cols)
        self.reporter.verbose(f"  [UNION] visible column index: {visible_col}")

        # Step 3 - Extract data
        extracted = self._extract_union_data(endpoint, param, num_cols, visible_col)

        detail = (
            f"UNION injection confirmed | "
            f"Columns: {num_cols} | "
            f"Reflected column index: {visible_col}"
        )
        self._record(
            endpoint, param, union_null_probe(num_cols),
            injection_type="Union-Based",
            detail=detail,
            severity="CRITICAL",
            extracted=extracted,
        )

    def _find_column_count(self, endpoint: dict, param: str) -> int:
        """ORDER BY binary approach, then NULL probing fallback."""
        # Phase A: ORDER BY escalation - error when n > col count
        prev_ok = False
        for n in range(1, 25):
            if self._should_stop():
                return None
            payload = union_order_by(n)
            try:
                resp = self._make_request(endpoint, param, payload)
                if resp is None:
                    break

                body_low = resp.text.lower()
                has_err  = (
                    resp.status_code in (500, 400)
                    or any(sig in body_low for sig in ERROR_SIGNATURES)
                )
                if has_err:
                    return n - 1 if n > 1 else None
                prev_ok = True

            except Exception:
                return n - 1 if prev_ok else None

        # Phase B: NULL probing - success when count matches exactly
        for n in range(1, 25):
            if self._should_stop():
                return None
            payload = union_null_probe(n)
            try:
                resp = self._make_request(endpoint, param, payload)
                if resp is None:
                    continue

                body_low = resp.text.lower()
                has_err  = (
                    resp.status_code in (500, 400)
                    or any(sig in body_low for sig in ERROR_SIGNATURES)
                )
                if not has_err and resp.status_code == 200:
                    return n

            except Exception:
                continue

        return None

    def _find_visible_column(self, endpoint: dict, param: str, num_cols: int) -> int:
        """Inject a unique marker into each column position to find reflection."""
        marker = "SQSCOUTMARKER7K3X"

        for idx in range(num_cols):
            if self._should_stop():
                return 0
            cols = ["NULL"] * num_cols
            cols[idx] = f"'{marker}'"
            payload = union_extract(cols)
            try:
                resp = self._make_request(endpoint, param, payload)
                if resp and marker in resp.text:
                    return idx
            except Exception:
                continue

        return 0  # Default - first column

    def _extract_union_data(self, endpoint: dict, param: str,
                            num_cols: int, visible_col: int) -> dict:
        """Run all known extraction queries against the confirmed injection."""
        extracted = {}

        for label, query in UNION_EXTRACT_QUERIES.items():
            if self._should_stop():
                break
            try:
                resp = self._make_request(endpoint, param, query)
                if not resp or resp.status_code not in (200, 201):
                    continue

                # Juice Shop wraps results in {"data": [...]}
                parsed = safe_json_parse(resp.text)
                if parsed and isinstance(parsed, dict) and "data" in parsed:
                    items = parsed["data"]
                    if isinstance(items, list) and items:
                        # Pull the first item's first string field
                        row = items[0]
                        if isinstance(row, dict):
                            value = next(
                                (str(v) for v in row.values() if v is not None), None
                            )
                        else:
                            value = str(row)
                        if value:
                            extracted[label] = truncate(value, 300)
                elif resp.text and len(resp.text.strip()) > 2:
                    extracted[label] = truncate(resp.text.strip(), 300)

            except Exception as e:
                self.reporter.verbose(f"  extraction query '{label}' failed: {e}")

        return extracted

    # HTTP Request Helper

    def _make_request(self, endpoint: dict, param: str, payload: str):
        """
        Build and fire an HTTP request with `payload` injected into `param`.
        Handles GET params, POST form data, and JSON bodies transparently.
        """
        url     = endpoint["url"]
        method  = endpoint["method"]
        ep_type = endpoint.get("type", "")
        timeout = self.config.get("timeout", 10)

        params = dict(endpoint.get("params") or {})
        data   = dict(endpoint.get("data")   or {})

        # Inject into the right place
        if param in params:
            params[param] = payload
        elif param in data:
            data[param] = payload
        else:
            # Unknown param - inject into query string for GET, body for POST
            if method == "GET":
                params[param] = payload
            else:
                data[param] = payload

        self.reporter.verbose(
            f"REQUEST {method} {url} param={param} payload={payload} "
            f"params={params} data={data} timeout={timeout}")

        try:
            if method == "GET":
                return self.session.get(url, params=params, timeout=timeout)

            elif method == "POST":
                if ep_type == "api_json":
                    return self.session.post(url, json=data, timeout=timeout)
                else:
                    return self.session.post(url, data=data, timeout=timeout)

            else:
                return self.session.request(
                    method, url, params=params, data=data, timeout=timeout
                )

        except requests.exceptions.Timeout:
            raise   # Re-raise - time-based detector needs to see this
        except Exception:
            return None

    # Result Recording

    def _record(self, endpoint: dict, param: str, payload: str,
                injection_type: str, detail: str, severity: str,
                extracted: dict = None):
        """
        Thread-safe. Records a vulnerability once per (url, param, type) triplet.
        """
        key = (endpoint["url"], param, injection_type)

        with self._lock:
            if key in self._recorded:
                return
            self._recorded.add(key)

            vuln = {
                "url":            endpoint["url"],
                "http_method":    endpoint["method"],
                "parameter":      param,
                "injection_type": injection_type,
                "severity":       severity,
                "payload":        payload,
                "detail":         detail,
                "timestamp":      time.strftime("%Y-%m-%d %H:%M:%S"),
                "method":         endpoint["method"],
            }
            if extracted:
                vuln["extracted_data"] = extracted

            self.results["vulnerabilities"].append(vuln)

        self.reporter.vulnerability(vuln)
