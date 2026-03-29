
# reporter.py - Colorized CLI Reporter for SQLi Scout

import sys
import json

try:
    from colorama import Fore, Back, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False

    # Stub so the rest of the code doesn't need guards everywhere
    class _FakeFore:
        def __getattr__(self, _): return ""
    class _FakeStyle:
        def __getattr__(self, _): return ""
    Fore  = _FakeFore()
    Style = _FakeStyle()
    Back  = _FakeFore()


SEVERITY_COLOR = {
    "CRITICAL": Fore.RED + Style.BRIGHT,
    "HIGH":     Fore.RED,
    "MEDIUM":   Fore.YELLOW,
    "LOW":      Fore.CYAN,
    "INFO":     Fore.WHITE,
}


class Reporter:
    def __init__(self, config: dict):
        self.config       = config
        self.verbose_mode = config.get("verbose", False)
        self._vuln_count  = 0

    # Section / structural output

    def section(self, title: str):
        bar = "═" * 62
        print(f"\n{Fore.CYAN}{bar}")
        print(f"  {Style.BRIGHT}{Fore.CYAN}{title}")
        print(f"{Fore.CYAN}{bar}{Style.RESET_ALL}")

    def banner(self):
        lines = [
            "",
            f"{Fore.RED + Style.BRIGHT}  ███████╗ ██████╗ ██╗     ██╗    ███████╗ ██████╗ ██████╗ ██╗   ██╗████████╗",
            f"  ██╔════╝██╔═══██╗██║     ██║    ██╔════╝██╔════╝██╔═══██╗██║   ██║╚══██╔══╝",
            f"  ███████╗██║   ██║██║     ██║    ███████╗██║     ██║   ██║██║   ██║   ██║   ",
            f"  ╚════██║██║▄▄ ██║██║     ██║    ╚════██║██║     ██║   ██║██║   ██║   ██║   ",
            f"  ███████║╚██████╔╝███████╗██║    ███████║╚██████╗╚██████╔╝╚██████╔╝   ██║   ",
            f"  ╚══════╝ ╚══▀▀═╝ ╚══════╝╚═╝    ╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝  {Style.RESET_ALL}",
            "",
            f"  {Fore.YELLOW}Advanced SQL Injection Scanner  |  Use only on authorized targets{Style.RESET_ALL}",
            f"  {Fore.WHITE}Designed for OWASP Juice Shop testing{Style.RESET_ALL}",
            "",
        ]
        for line in lines:
            print(line)

    # Logging levels

    def info(self, msg: str):
        print(f"  {Fore.BLUE}[*]{Style.RESET_ALL} {msg}")

    def success(self, msg: str):
        print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} {msg}")

    def warning(self, msg: str):
        print(f"  {Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")

    def error(self, msg: str):
        print(f"  {Fore.RED}[FAIL]{Style.RESET_ALL} {msg}", file=sys.stderr)

    def verbose(self, msg: str):
        if self.verbose_mode:
            print(f"  {Fore.WHITE}[~]{Style.RESET_ALL} {msg}")

    # Vulnerability alert

    def vulnerability(self, vuln: dict):
        self._vuln_count += 1
        sev   = vuln.get("severity", "INFO")
        color = SEVERITY_COLOR.get(sev, "")
        bar   = "─" * 60

        print(f"\n  {Fore.RED}{'━' * 60}{Style.RESET_ALL}")
        print(f"  {Fore.RED + Style.BRIGHT}  [!]  VULNERABILITY #{self._vuln_count}  [!]{Style.RESET_ALL}")
        print(f"  {Fore.RED}{'━' * 60}{Style.RESET_ALL}")

        rows = [
            ("Severity",  f"{color}{sev}{Style.RESET_ALL}"),
            ("Type",      vuln.get("injection_type", "?")),
            ("URL",       vuln.get("url", "?")),
            ("Parameter", f"{Fore.YELLOW}{vuln.get('parameter', '?')}{Style.RESET_ALL}"),
            ("Method",    vuln.get("method", "?")),
            ("Payload",   f"{Fore.GREEN}{str(vuln.get('payload',''))[:80]}{Style.RESET_ALL}"),
            ("Detail",    vuln.get("detail", "")),
        ]
        for label, value in rows:
            print(f"  {Fore.WHITE}{label:<12}{Style.RESET_ALL}: {value}")

        extracted = vuln.get("extracted_data")
        if extracted:
            print(f"  {Fore.CYAN}{'─' * 40}{Style.RESET_ALL}")
            print(f"  {Fore.CYAN + Style.BRIGHT}  EXTRACTED DATA{Style.RESET_ALL}")
            for k, v in extracted.items():
                val = str(v)
                print(f"  {Fore.YELLOW}  {k}{Style.RESET_ALL}: {val[:200]}")

        print()

    # Summary table

    def summary(self, results: dict):
        self.section("SCAN SUMMARY")
        vulns = results.get("vulnerabilities", [])

        self.info(f"Target            : {results.get('target')}")
        self.info(f"Scan started      : {results.get('scan_start')}")
        self.info(f"Scan finished     : {results.get('scan_end', 'N/A')}")
        self.info(f"Endpoints tested  : {results.get('endpoints_tested', 0)}")
        self.info(f"Parameters tested : {results.get('params_tested', 0)}")
        self.info(f"Vulnerabilities   : {len(vulns)}")

        if vulns:
            counts: dict = {}
            for v in vulns:
                s = v.get("severity", "?")
                counts[s] = counts.get(s, 0) + 1

            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                if sev in counts:
                    color = SEVERITY_COLOR.get(sev, "")
                    print(f"    {color}{sev:<10}{Style.RESET_ALL}: {counts[sev]}")

            print()
            self.success("Vulnerable endpoints:")
            for v in vulns:
                sev   = v.get("severity", "?")
                color = SEVERITY_COLOR.get(sev, "")
                print(
                    f"    {color}[{sev}]{Style.RESET_ALL} "
                    f"{v.get('injection_type'):<22} "
                    f"{v.get('url')}  "
                    f"{Fore.YELLOW}?{v.get('parameter')}{Style.RESET_ALL}"
                )
        else:
            self.info("No vulnerabilities found.")

    # File output

    def save_to_file(self, results: dict, path: str):
        """Save full results dict as formatted JSON."""
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, default=str)
            self.success(f"Results saved → {path}")
        except Exception as e:
            self.error(f"Could not save results: {e}")
