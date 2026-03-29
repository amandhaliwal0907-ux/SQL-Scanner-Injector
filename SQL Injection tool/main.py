#!/usr/bin/env python3
"""
main.py - SQLi Scout Entry Point

Usage examples:
  python main.py -u http://localhost:3000
  python main.py -u http://localhost:3000 --methods error boolean
  python main.py -u http://localhost:3000/rest/products/search?q=test --no-crawl
  python main.py -u http://localhost:3000 --threads 10 --output results.json -v
  python main.py -u http://localhost:3000 --cookies "token=abc123"
"""

import sys
import argparse

from reporter import Reporter
from scanner  import SQLiScanner


def parse_args():
    parser = argparse.ArgumentParser(
        prog="sqli-scout",
        description=(
            "SQLi Scout - Advanced SQL Injection Scanner\n"
            "For authorized security testing only.\n"
            "Optimised for OWASP Juice Shop."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Detection methods:
  error    - Trigger visible DB error messages
  boolean  - Infer injection via true/false response divergence
  time     - Detect blind injection via artificial DB delays
  union    - Extract real data once injection is confirmed

Examples:
  Full auto-scan (all methods, auto-crawl):
    python main.py -u http://localhost:3000

  Target a specific param, error + boolean only:
    python main.py -u http://localhost:3000/rest/products/search?q=test \\
                   --no-crawl --methods error boolean

  Deep crawl, 10 threads, save results:
    python main.py -u http://localhost:3000 --crawl-depth 3 \\
                   --threads 10 --output results.json -v

  With auth token:
    python main.py -u http://localhost:3000 \\
                   --headers "Authorization: Bearer <token>"
        """,
    )

    # ── Required ──────────────────────────────────────────────────────────────
    parser.add_argument(
        "-u", "--url",
        required=True,
        metavar="URL",
        help="Target URL (e.g. http://localhost:3000)",
    )

    # ── Scope ─────────────────────────────────────────────────────────────────
    parser.add_argument(
        "--no-crawl",
        action="store_true",
        help="Skip crawling; test only the URL/params you supply directly",
    )
    parser.add_argument(
        "--crawl-depth",
        type=int,
        default=2,
        metavar="N",
        help="How many link-hops deep to crawl (default: 2)",
    )

    # ── Detection methods ─────────────────────────────────────────────────────
    parser.add_argument(
        "--methods",
        nargs="+",
        choices=["error", "boolean", "time", "union"],
        default=["error", "boolean", "time", "union"],
        metavar="METHOD",
        help="Detection methods to use (default: all four)",
    )

    # ── Performance ───────────────────────────────────────────────────────────
    parser.add_argument(
        "--threads",
        type=int,
        default=5,
        metavar="N",
        help="Concurrent threads (default: 5)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        metavar="SEC",
        help="HTTP request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        metavar="SEC",
        help="Delay between requests in seconds (default: 0)",
    )
    parser.add_argument(
        "--time-threshold",
        type=float,
        default=4.0,
        metavar="SEC",
        help="Minimum delay to flag as time-based injection (default: 4.0)",
    )

    # ── Auth / HTTP ───────────────────────────────────────────────────────────
    parser.add_argument(
        "--headers",
        nargs="+",
        metavar="HEADER",
        help="Custom HTTP headers, e.g. 'Authorization: Bearer abc'",
    )
    parser.add_argument(
        "--cookies",
        metavar="COOKIES",
        help="Cookie string, e.g. 'session=abc; token=xyz'",
    )

    # ── Evasion ───────────────────────────────────────────────────────────────
    parser.add_argument(
        "--no-waf-evasion",
        action="store_true",
        help="Disable WAF evasion payload variants",
    )

    # ── Output ────────────────────────────────────────────────────────────────
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Save full results to a JSON file",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print every request detail",
    )

    return parser.parse_args()


def build_config(args) -> dict:
    # Parse --headers list into a dict
    custom_headers = {}
    if args.headers:
        for h in args.headers:
            if ":" in h:
                k, v = h.split(":", 1)
                custom_headers[k.strip()] = v.strip()

    # Parse --cookies string into a dict
    cookies = {}
    if args.cookies:
        for pair in args.cookies.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()

    return {
        "target":         args.url,
        "crawl_depth":    args.crawl_depth,
        "no_crawl":       args.no_crawl,
        "methods":        args.methods,
        "threads":        args.threads,
        "timeout":        args.timeout,
        "delay":          args.delay,
        "time_threshold": args.time_threshold,
        "output":         args.output,
        "headers":        custom_headers,
        "cookies":        cookies,
        "waf_evasion":    not args.no_waf_evasion,
        "verbose":        args.verbose,
    }


def main():
    args   = parse_args()
    config = build_config(args)

    reporter = Reporter(config)
    reporter.banner()

    scanner = SQLiScanner(config, reporter)

    try:
        scanner.run()
    except KeyboardInterrupt:
        reporter.warning("\nScan interrupted - saving partial results…")
        # Ensure scan_end is set
        import time
        scanner.results["scan_end"] = time.strftime("%Y-%m-%d %H:%M:%S")
        if config.get("output"):
            reporter.save_to_file(scanner.results, config["output"])
        sys.exit(130)


if __name__ == "__main__":
    main()
