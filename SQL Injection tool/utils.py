
# utils.py - Helper utilities for SQLi Scout

import re
import time
import difflib
from urllib.parse import (
    urlparse, urljoin, parse_qs, urlencode, urlunparse
)


# URL Helpers

def normalize_url(url: str) -> str:
    """Ensure URL has an http:// scheme."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


def get_base_url(url: str) -> str:
    """Return scheme + host only (no path)."""
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def inject_into_url_param(url: str, param: str, payload: str) -> str:
    """Return URL with a specific query parameter replaced by payload."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urlencode({k: v[0] for k, v in params.items()})
    return urlunparse(parsed._replace(query=new_query))


def extract_url_params(url: str) -> dict:
    """Return query-string parameters as a flat dict."""
    parsed = urlparse(url)
    raw = parse_qs(parsed.query, keep_blank_values=True)
    return {k: v[0] for k, v in raw.items()}


def clean_url(url: str) -> str:
    """Strip fragment (#) from URL."""
    parsed = urlparse(url)
    return urlunparse(parsed._replace(fragment=""))


def is_same_domain(url: str, base: str) -> bool:
    """Return True if url belongs to the same host as base."""
    return urlparse(url).netloc == urlparse(base).netloc


def is_injectable_content_type(ct: str) -> bool:
    """Return True for content types that carry reflectable data."""
    injectable = [
        "text/html", "application/json", "text/plain",
        "application/xml", "text/xml",
    ]
    return any(t in ct.lower() for t in injectable)


# Response Comparison

def response_similarity(a: str, b: str) -> float:
    """Return a 0.0–1.0 similarity ratio between two response bodies."""
    return difflib.SequenceMatcher(None, a, b).ratio()


def responses_differ_significantly(r_true: str, r_false: str,
                                   baseline: str,
                                   min_divergence: float = 0.1,
                                   max_true_false_sim: float = 0.85) -> tuple:
    """
    Boolean-injection heuristic.
    Returns (is_injectable: bool, details: dict).
    """
    sim_tf  = response_similarity(r_true, r_false)
    sim_tb  = response_similarity(baseline, r_true)
    sim_fb  = response_similarity(baseline, r_false)
    diff    = abs(sim_tb - sim_fb)

    injectable = sim_tf < max_true_false_sim and diff > min_divergence
    return injectable, {
        "true_false_sim": round(sim_tf, 3),
        "true_baseline_sim": round(sim_tb, 3),
        "false_baseline_sim": round(sim_fb, 3),
        "divergence": round(diff, 3),
    }


# Timing

def timed_call(fn, *args, **kwargs):
    """
    Call fn(*args, **kwargs) and return (result, elapsed_seconds).
    elapsed is measured as wall-clock time.
    """
    t0 = time.perf_counter()
    result = fn(*args, **kwargs)
    elapsed = time.perf_counter() - t0
    return result, elapsed


# Misc

def truncate(s: str, max_len: int = 100) -> str:
    """Truncate a string for display."""
    if len(s) <= max_len:
        return s
    return s[:max_len] + "…"


def safe_json_parse(text: str):
    """Return parsed JSON or None if parsing fails."""
    import json
    try:
        return json.loads(text)
    except Exception:
        return None


def extract_js_api_paths(html: str) -> list:
    """
    Scan inline JS / HTML for API-looking paths.
    Returns list of path strings starting with /.
    """
    patterns = [
        r'''["'](/(?:api|rest|graphql)/[^"'?\s]{2,}(?:\?[^"']*)?)['"]\s*[,\);]''',
        r'''fetch\s*\(\s*["']([^"']+)["']''',
        r'''axios\.\w+\s*\(\s*["']([^"']+)["']''',
        r'''url\s*:\s*["']([^"']+)["']''',
    ]
    found = set()
    for pattern in patterns:
        for m in re.findall(pattern, html, re.IGNORECASE):
            if m.startswith("/") or m.startswith("http"):
                found.add(m)
    return list(found)


def parse_qs_flat(qs: str) -> dict:
    """Parse a query string into a flat dict (first value wins)."""
    result = {}
    for pair in qs.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            result[k.strip()] = v.strip()
    return result
