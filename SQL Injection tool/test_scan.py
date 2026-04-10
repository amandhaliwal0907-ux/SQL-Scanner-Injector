#!/usr/bin/env python3
"""
Test script to run the SQL injection scanner programmatically
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from scanner import SQLiScanner
from reporter import Reporter

def test_scan():
    # Test configuration
    config = {
        "target": "http://localhost:3000",  # Adjust this to your test target
        "methods": ["error"],  # Start with just one method
        "threads": 1,  # Reduce threads
        "timeout": 5,  # Shorter timeout
        "delay": 0,
        "waf_evasion": False,  # Disable WAF evasion for now
        "no_crawl": True,  # Disable crawling to test basic functionality first
        "log_file": "test_scan.log",
        "verbose": True
    }

    # Create reporter
    reporter = Reporter(config)

    # Create and run scanner
    scanner = SQLiScanner(config, reporter)
    scanner.run()

    # Print results
    results = scanner.results
    print(f"\n=== SCAN RESULTS ===")
    print(f"Target: {results['target']}")
    print(f"Endpoints tested: {results['endpoints_tested']}")
    print(f"Parameters tested: {results['params_tested']}")
    print(f"Vulnerabilities found: {len(results['vulnerabilities'])}")

    for vuln in results['vulnerabilities']:
        print(f"  - {vuln['severity']}: {vuln['description']} at {vuln['url']} param={vuln['param']}")

if __name__ == "__main__":
    test_scan()