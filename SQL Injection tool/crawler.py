
# crawler.py - Endpoint Discovery Engine
# Discovers injection points via:
#   - HTML form parsing (GET and POST)
#   - URL query-parameter extraction
#   - JavaScript API path scanning
#   - Universal common path probing (works on any website)
#   - Recursive link-following up to max_depth

import time
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

from utils import (
    normalize_url, get_base_url, clean_url,
    is_same_domain, extract_js_api_paths, parse_qs_flat
)


# Universal common paths probed on every target.

COMMON_GET_PATHS = [
    # Search / query params - most common injection surface
    ("/search",          {"q": "test"}),
    ("/search.php",      {"q": "test"}),
    ("/search.asp",      {"q": "test"}),
    ("/search.aspx",     {"q": "test"}),
    ("/find",            {"q": "test"}),
    ("/query",           {"q": "test"}),
    ("/results",         {"q": "test"}),
    # Item / product / article by ID
    ("/item",            {"id": "1"}),
    ("/product",         {"id": "1"}),
    ("/products",        {"id": "1"}),
    ("/article",         {"id": "1"}),
    ("/post",            {"id": "1"}),
    ("/page",            {"id": "1"}),
    ("/news",            {"id": "1"}),
    ("/view",            {"id": "1"}),
    ("/detail",          {"id": "1"}),
    ("/show",            {"id": "1"}),
    ("/profile",         {"id": "1"}),
    ("/user",            {"id": "1"}),
    # Category / filter params
    ("/category",        {"cat": "1"}),
    ("/categories",      {"id": "1"}),
    ("/filter",          {"filter": "all"}),
    ("/list",            {"page": "1"}),
    # Common PHP patterns
    ("/index.php",       {"id": "1"}),
    ("/index.php",       {"page": "home"}),
    ("/news.php",        {"id": "1"}),
    ("/article.php",     {"id": "1"}),
    ("/product.php",     {"id": "1"}),
    ("/category.php",    {"id": "1"}),
    ("/profile.php",     {"id": "1"}),
    ("/user.php",        {"id": "1"}),
    ("/view.php",        {"id": "1"}),
    ("/download.php",    {"file": "test"}),
    # REST-style APIs - common on modern apps
    ("/api/search",      {"q": "test"}),
    ("/api/products",    {"id": "1"}),
    ("/api/users",       {"id": "1"}),
    ("/api/items",       {"id": "1"}),
    ("/api/posts",       {"id": "1"}),
    ("/api/articles",    {"id": "1"}),
    ("/api/v1/search",   {"q": "test"}),
    ("/api/v1/products", {"id": "1"}),
    ("/api/v1/users",    {"id": "1"}),
    ("/api/v2/search",   {"q": "test"}),
    ("/api/v2/products", {"id": "1"}),
    # Juice Shop specific (only resolves if target is Juice Shop)
    ("/rest/products/search", {"q": "test"}),
    ("/rest/track-order/1",   {}),
]

COMMON_POST_PATHS = [
    # Login forms - highest value target
    ("/login",           {"username": "test", "password": "test"},   "form"),
    ("/login.php",       {"username": "test", "password": "test"},   "form"),
    ("/login.asp",       {"username": "test", "password": "test"},   "form"),
    ("/login.aspx",      {"username": "test", "password": "test"},   "form"),
    ("/signin",          {"username": "test", "password": "test"},   "form"),
    ("/sign-in",         {"username": "test", "password": "test"},   "form"),
    ("/account/login",   {"username": "test", "password": "test"},   "form"),
    ("/user/login",      {"username": "test", "password": "test"},   "form"),
    ("/auth/login",      {"username": "test", "password": "test"},   "form"),
    # JSON login APIs
    ("/api/login",       {"username": "test", "password": "test"},   "json"),
    ("/api/auth",        {"username": "test", "password": "test"},   "json"),
    ("/api/v1/login",    {"username": "test", "password": "test"},   "json"),
    ("/api/v1/auth",     {"username": "test", "password": "test"},   "json"),
    ("/rest/user/login", {"email": "test@test.com", "password": "test"}, "json"),
    # Contact / comment / feedback forms
    ("/contact",         {"name": "test", "email": "test@test.com", "message": "test"}, "form"),
    ("/contact.php",     {"name": "test", "email": "test@test.com", "message": "test"}, "form"),
    ("/feedback",        {"comment": "test", "rating": "5"},         "form"),
    ("/comment",         {"comment": "test"},                         "form"),
    # Search via POST
    ("/search",          {"q": "test"},                               "form"),
    ("/search.php",      {"q": "test"},                               "form"),
    # Register
    ("/register",        {"username": "test", "email": "t@t.com", "password": "test"}, "form"),
    ("/signup",          {"username": "test", "email": "t@t.com", "password": "test"}, "form"),
]


class Crawler:
    def __init__(self, config: dict, session: requests.Session, reporter=None, stop_flag=None):
        self.config   = config
        self.session  = session
        self.reporter = reporter
        self._stop_flag = stop_flag  # Callable that returns True if crawl should stop

        target = normalize_url(config["target"])
        self.base_url  = get_base_url(target)
        self.start_url = target

        self.visited   = set()
        self.endpoints = []          # collected injection targets
        self.max_depth = config.get("crawl_depth", 2)
        self.max_pages = config.get("max_crawl_pages", 100)  # Limit pages to prevent memory issues
        self.max_endpoints = config.get("max_endpoints", 200)  # Limit endpoints
        self.timeout   = config.get("timeout", 10)
        self.delay     = config.get("delay", 0)
        self.verbose   = config.get("verbose", False)

    def _should_stop(self):
        """Check if crawl should be stopped."""
        return self._stop_flag and self._stop_flag()

    # Public entry point

    def crawl(self) -> list:
        self._log(f"Starting crawl: {self.start_url}  (depth={self.max_depth}, max_pages={self.max_pages})")

        # 1. Probe universal common paths (only adds ones that respond)
        self._probe_common_paths()

        # 2. Recursively crawl HTML pages
        self._crawl_page(self.start_url, depth=0)

        # 3. De-duplicate
        self.endpoints = self._deduplicate(self.endpoints)

        self._log(f"Discovery complete - {len(self.endpoints)} injection point(s) found")
        return self.endpoints

    # Known-API seeding

    def _probe_common_paths(self):
        """
        Silently probe universal common paths.
        Only adds an endpoint if the server actually responds (not 404/timeout).
        This makes the seeding work on any website, not just Juice Shop.
        """
        added = 0
        for path, params in COMMON_GET_PATHS:
            if self._should_stop() or len(self.endpoints) >= self.max_endpoints:
                break
            url = self.base_url + path
            try:
                resp = self.session.get(url, params=params,
                                        timeout=min(self.timeout, 5),
                                        allow_redirects=True)
                # Only add if server returned something meaningful (not 404/410/501)
                if resp.status_code not in (404, 405, 410, 501, 502, 503):
                    self.endpoints.append({
                        "url":    url,
                        "method": "GET",
                        "params": params,
                        "data":   None,
                        "type":   "api",
                    })
                    added += 1
                    if self.verbose:
                        self._log(f"  [probe OK] GET {path} ({resp.status_code})")
            except Exception:
                pass  # Path doesn't exist on this server - skip silently

        for path, data, req_type in COMMON_POST_PATHS:
            if self._should_stop() or len(self.endpoints) >= self.max_endpoints:
                break
            url = self.base_url + path
            try:
                if req_type == "json":
                    resp = self.session.post(url, json=data,
                                             timeout=min(self.timeout, 5))
                else:
                    resp = self.session.post(url, data=data,
                                             timeout=min(self.timeout, 5))
                if resp.status_code not in (404, 405, 410, 501, 502, 503):
                    self.endpoints.append({
                        "url":    url,
                        "method": "POST",
                        "params": {},
                        "data":   data,
                        "type":   "api_json" if req_type == "json" else "form",
                    })
                    added += 1
                    if self.verbose:
                        self._log(f"  [probe OK] POST {path} ({resp.status_code})")
            except Exception:
                pass

        if added:
            self._log(f"Universal probe: {added} responsive path(s) found")

    # Recursive HTML crawler

    def _crawl_page(self, url: str, depth: int):
        if self._should_stop():
            return
        if len(self.visited) >= self.max_pages:
            self._log(f"Reached maximum page limit ({self.max_pages})")
            return
        if len(self.endpoints) >= self.max_endpoints:
            self._log(f"Reached maximum endpoint limit ({self.max_endpoints})")
            return

        url = clean_url(url)

        if url in self.visited or depth > self.max_depth:
            return
        self.visited.add(url)

        if self.verbose:
            self._log(f"  Crawling (depth={depth}): {url}")

        # Fetch page
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
        except Exception as e:
            if self.verbose:
                self._log(f"  [!] Fetch failed {url}: {e}")
            return

        if self.delay:
            time.sleep(self.delay)

        ct = resp.headers.get("Content-Type", "")
        if "text/html" not in ct:
            return                 # skip non-HTML (JS, CSS, images …)

        # Extract URL params from this page
        parsed = urlparse(url)
        if parsed.query:
            self.endpoints.append({
                "url":    url.split("?")[0],
                "method": "GET",
                "params": parse_qs_flat(parsed.query),
                "data":   None,
                "type":   "url_param",
            })

        soup = BeautifulSoup(resp.text, "html.parser")

        # Harvest forms
        for form in soup.find_all("form"):
            if self._should_stop() or len(self.endpoints) >= self.max_endpoints:
                break
            ep = self._parse_form(url, form)
            if ep:
                self.endpoints.append(ep)

        # Scan inline JS for API paths
        for path in extract_js_api_paths(resp.text):
            if self._should_stop() or len(self.endpoints) >= self.max_endpoints:
                break
            self._js_path_to_endpoint(path)

        # Follow internal links
        if depth < self.max_depth:
            for tag in soup.find_all("a", href=True):
                if self._should_stop() or len(self.visited) >= self.max_pages:
                    break
                href   = tag["href"]
                target = clean_url(urljoin(url, href))
                if is_same_domain(target, self.base_url) and target not in self.visited:
                    self._crawl_page(target, depth + 1)

    # Form parser

    def _parse_form(self, page_url: str, form) -> dict:
        action = form.get("action") or page_url
        method = (form.get("method") or "GET").upper()
        form_url = urljoin(page_url, action)

        fields = {}
        for tag in form.find_all(["input", "textarea", "select"]):
            name = tag.get("name")
            if not name:
                continue
            # Use existing value or a neutral placeholder
            fields[name] = tag.get("value") or "test"

        if not fields:
            return None

        return {
            "url":    form_url,
            "method": method,
            "params": fields if method == "GET" else {},
            "data":   fields if method == "POST" else None,
            "type":   "form",
        }

    # JS path handling

    def _js_path_to_endpoint(self, path: str):
        if path.startswith("http"):
            full = path
        elif path.startswith("/"):
            full = self.base_url + path
        else:
            return

        if not is_same_domain(full, self.base_url):
            return

        if "?" in full:
            base, qs = full.split("?", 1)
            self.endpoints.append({
                "url":    base,
                "method": "GET",
                "params": parse_qs_flat(qs),
                "data":   None,
                "type":   "api",
            })
        else:
            self.endpoints.append({
                "url":    full,
                "method": "GET",
                "params": {},
                "data":   None,
                "type":   "api",
            })

    # Deduplication

    @staticmethod
    def _deduplicate(endpoints: list) -> list:
        seen   = set()
        unique = []
        for ep in endpoints:
            key = (
                ep["url"],
                ep["method"],
                str(sorted(ep.get("params", {}).items())),
                str(sorted((ep.get("data") or {}).items())),
            )
            if key not in seen:
                seen.add(key)
                unique.append(ep)
        return unique

    # Logging

    def _log(self, msg: str):
        if self.reporter:
            self.reporter.info(msg)
        else:
            print(f"  [*] {msg}")