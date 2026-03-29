# SQLi Scout 🔍

Advanced SQL Injection Scanner - built for authorized security testing.
Pre-configured for **OWASP Juice Shop**.

> **Legal notice:** Only use against systems you have explicit permission to test.
> OWASP Juice Shop is an intentionally vulnerable app designed for this purpose.

---

## Features

| Method | Description |
|---|---|
| **Error-Based** | Triggers visible DB error messages; fastest detection |
| **Boolean-Based Blind** | Infers injection via true/false response divergence |
| **Time-Based Blind** | Confirms blind injection by measuring artificial DB delays |
| **Union-Based** | Extracts real data (tables, credentials, schema) once injection confirmed |

Additional capabilities:
- **Auto-crawler** - discovers forms, URL params, and API endpoints automatically
- **Juice Shop pre-seeding** - 10+ known injectable endpoints tested automatically
- **WAF evasion** - comment injection, case variation, URL/double encoding, null bytes
- **Multi-threaded** - configurable thread count for fast parallel scanning
- **JSON output** - full structured results saved to file
- **Colorized CLI** - severity-coded terminal output

---

## Setup

```bash
# 1. Clone / download the tool
cd sqli_scout

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start OWASP Juice Shop (Docker)
docker pull bkimminich/juice-shop
docker run -d -p 3000:3000 bkimminich/juice-shop
```

---

## Usage

### Full auto-scan (recommended starting point)
```bash
python main.py -u http://localhost:3000
```

### Target a specific endpoint only
```bash
python main.py -u "http://localhost:3000/rest/products/search?q=apple" --no-crawl
```

### Choose specific methods
```bash
python main.py -u http://localhost:3000 --methods error boolean
```

### Deep crawl with more threads + save results
```bash
python main.py -u http://localhost:3000 --crawl-depth 3 --threads 10 --output results.json -v
```

### With an auth token (after logging in to Juice Shop)
```bash
python main.py -u http://localhost:3000 \
               --headers "Authorization: Bearer <your_jwt_token>"
```

### All options
```
-u / --url URL            Target URL (required)
--no-crawl                Skip crawling, test only the given URL
--crawl-depth N           Link-hop depth for crawling (default: 2)
--methods METHOD [...]    error / boolean / time / union (default: all)
--threads N               Concurrent threads (default: 5)
--timeout SEC             HTTP timeout seconds (default: 10)
--delay SEC               Delay between requests (default: 0)
--time-threshold SEC      Min delay to flag time-based injection (default: 4.0)
--headers HEADER [...]    Custom HTTP headers
--cookies COOKIES         Cookie string
--no-waf-evasion          Disable WAF evasion payload variants
-o / --output FILE        Save results as JSON
-v / --verbose            Print every request detail
```

---

## Architecture

```
sqli_scout/
├── main.py        CLI entry point (argparse, config building)
├── scanner.py     Core detection engine (all 4 methods, threading)
├── crawler.py     Endpoint discovery (forms, URL params, JS APIs)
├── payloads.py    Payload library + WAF evasion generators
├── reporter.py    Colorized CLI output + JSON file saving
├── utils.py       Helpers (URL manipulation, response diffing, timing)
└── requirements.txt
```

### Detection chain

```
Crawl site
    │
    ▼
For each endpoint × parameter:
    │
    ├─► Error-Based   ─ inject ' and variants → check response for SQL errors
    │
    ├─► Boolean-Based ─ inject AND 1=1 / AND 1=2 → compare response similarity
    │
    ├─► Time-Based    ─ inject SLEEP(5) variants → measure wall-clock delay
    │
    └─► Union-Based   ─ find column count → find visible column → extract data
```

### Juice Shop Known Attack Surfaces

| Endpoint | Method | Injectable |
|---|---|---|
| `/rest/products/search?q=` | GET | `q` param |
| `/rest/user/login` | POST JSON | `email`, `password` |
| `/rest/user/register` | POST JSON | `email` |
| `/api/Products` | GET | id params |
| `/rest/feedback` | POST JSON | `comment` |

---

## Output

### Terminal (always on)
Color-coded per severity: `CRITICAL` → `HIGH` → `MEDIUM` → `LOW`

### JSON file (`--output results.json`)
```json
{
  "target": "http://localhost:3000",
  "scan_start": "2025-01-01 12:00:00",
  "scan_end":   "2025-01-01 12:03:42",
  "endpoints_tested": 14,
  "params_tested": 38,
  "vulnerabilities": [
    {
      "url": "http://localhost:3000/rest/products/search",
      "parameter": "q",
      "injection_type": "Error-Based",
      "severity": "HIGH",
      "payload": "'",
      "detail": "DB error string detected: «sqlite error»",
      "timestamp": "2025-01-01 12:00:05"
    }
  ]
}
```

---

## WAF Evasion Techniques

SQLi Scout automatically generates evasion variants of payloads:

| Technique | Example |
|---|---|
| Comment injection | `' OR/**/1=1--` |
| Case swapping | `' oR 1=1--` |
| URL encoding | `%27%20OR%201%3D1--` |
| Double URL encoding | `%2527` |
| Whitespace substitution | `'\tOR\t1=1--` |
| Null byte prefix | `%00'` |
| Keyword splitting | `' UN/**/ION SE/**/LECT--` |
