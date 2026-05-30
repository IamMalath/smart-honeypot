"""Rules-based attacker behaviour classifier.

Each captured request is reduced to a single dominant category. We check the
highest-severity signatures first (RCE, webshell) and fall through to the
lowest (benign / scanner). The result is deliberately deterministic so the
project can be evaluated against a ground-truth test set.
"""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass
from typing import Dict, Iterable, Optional, Tuple

# ---- Signature library -------------------------------------------------------
# Each signature is (compiled_regex, category, severity 0-3).

def _ci(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE)


SQLI_PATTERNS = [
    _ci(r"(?:'|%27).*(?:--|#|/\*)"),
    _ci(r"\bunion\b\s+\bselect\b"),
    _ci(r"\bor\b\s+1\s*=\s*1\b"),
    _ci(r"\band\b\s+\d+\s*=\s*\d+\b"),
    _ci(r"\bselect\b\s+.+\s+\bfrom\b\s+\binformation_schema\b"),
    _ci(r"\bsleep\s*\(\s*\d+\s*\)"),
    _ci(r"\bbenchmark\s*\("),
]

XSS_PATTERNS = [
    _ci(r"<\s*script[^>]*>"),
    _ci(r"javascript\s*:"),
    _ci(r"on(?:error|load|click|mouseover)\s*="),
    _ci(r"<\s*img[^>]+src\s*=\s*[\"']?javascript:"),
    _ci(r"document\.cookie"),
]

LFI_PATTERNS = [
    _ci(r"\.\./"),
    _ci(r"\.\.\\"),
    _ci(r"%2e%2e%2f"),
    _ci(r"/etc/passwd"),
    _ci(r"/proc/self/"),
    _ci(r"file:///"),
    _ci(r"php://(?:filter|input)"),
]

RCE_PATTERNS = [
    _ci(r";\s*(?:cat|ls|id|uname|wget|curl|whoami|nc|bash|sh)\b"),
    _ci(r"\|\s*(?:cat|ls|id|uname|wget|curl|whoami|nc|bash|sh)\b"),
    _ci(r"`[^`]+`"),
    _ci(r"\$\([^)]+\)"),
    _ci(r"\b(?:system|exec|passthru|shell_exec|popen)\s*\("),
    _ci(r"/bin/(?:bash|sh)\b"),
]

WEBSHELL_PATTERNS = [
    _ci(r"\b(?:c99|r57|wso|b374k)\b"),
    _ci(r"<\?php\s+(?:eval|system|exec|passthru|shell_exec)\s*\("),
    _ci(r"shell\.(?:php|jsp|aspx)"),
    _ci(r"upload(?:er)?\.php"),
]

SENSITIVE_FILE_PATHS = [
    _ci(r"/\.env(\?|$|/)"),
    _ci(r"/\.git/(?:config|HEAD)"),
    _ci(r"/wp-config\.php"),
    _ci(r"/config(?:uration)?\.(?:php|yml|yaml|json)"),
    _ci(r"/\.aws/credentials"),
    _ci(r"/backup(?:s)?\.(?:zip|tar|sql)"),
    _ci(r"/id_rsa(\?|$)"),
]

SCANNER_USER_AGENTS = [
    _ci(r"\bnikto\b"),
    _ci(r"\bsqlmap\b"),
    _ci(r"\bnmap\b"),
    _ci(r"\bmasscan\b"),
    _ci(r"\bzgrab\b"),
    _ci(r"\bgobuster\b"),
    _ci(r"\bdirb(?:uster)?\b"),
    _ci(r"\bferoxbuster\b"),
    _ci(r"\bwpscan\b"),
    _ci(r"\bcensys\b"),
    _ci(r"\bshodan\b"),
    _ci(r"\bcurl/"),
    _ci(r"\bpython-requests\b"),
]

LOGIN_PATHS = [
    "/login", "/admin", "/admin/login", "/wp-login.php",
    "/administrator", "/user/login", "/manager/html",
]

DEFAULT_CRED_PAIRS = {
    ("admin", "admin"), ("admin", "password"), ("admin", "12345"),
    ("admin", "admin123"), ("root", "root"), ("root", "toor"),
    ("user", "user"), ("test", "test"), ("administrator", "administrator"),
}


@dataclass
class Classification:
    category: str            # canonical category key
    severity: int            # 0..3
    matched_rule: str        # short description for the dashboard


def _join_payloads(req: Dict) -> str:
    parts = [
        req.get("path", "") or "",
        req.get("query_string", "") or "",
        req.get("body", "") or "",
    ]
    raw = "\n".join(parts)
    try:
        decoded = urllib.parse.unquote_plus(raw)
    except Exception:
        decoded = raw
    return raw + "\n" + decoded


def _match_any(patterns: Iterable[re.Pattern], haystack: str) -> Optional[str]:
    for p in patterns:
        if p.search(haystack):
            return p.pattern
    return None


def classify(req: Dict, cfg: Optional[Dict] = None) -> Classification:
    """Reduce one captured request to a single category + severity."""
    cfg = cfg or {}
    payload = _join_payloads(req)
    path = (req.get("path") or "").lower()
    ua = (req.get("user_agent") or "").lower()
    method = (req.get("method") or "GET").upper()

    # ---- highest severity first --------------------------------------------
    if cfg.get("enable_rce", True):
        m = _match_any(WEBSHELL_PATTERNS, payload)
        if m:
            return Classification("webshell", 3, f"webshell pattern: {m}")
        m = _match_any(RCE_PATTERNS, payload)
        if m:
            return Classification("rce", 3, f"rce pattern: {m}")

    if cfg.get("enable_sqli", True):
        m = _match_any(SQLI_PATTERNS, payload)
        if m:
            return Classification("sqli", 2, f"sqli pattern: {m}")

    if cfg.get("enable_xss", True):
        m = _match_any(XSS_PATTERNS, payload)
        if m:
            return Classification("xss", 2, f"xss pattern: {m}")

    if cfg.get("enable_lfi", True):
        m = _match_any(LFI_PATTERNS, payload)
        if m:
            cat = "lfi" if "passwd" in payload.lower() or "php://" in payload.lower() else "path_traversal"
            return Classification(cat, 2, f"lfi/traversal pattern: {m}")

    # sensitive file fetches (.env, .git/config, wp-config.php, ...)
    m = _match_any(SENSITIVE_FILE_PATHS, path)
    if m:
        return Classification("sensitive_file", 2, f"sensitive path: {m}")

    # brute force / default creds on login forms
    if cfg.get("enable_brute_force", True) and method == "POST" and any(
        path.startswith(p) for p in LOGIN_PATHS
    ):
        body = req.get("body") or ""
        try:
            form = urllib.parse.parse_qs(body, keep_blank_values=True)
        except Exception:
            form = {}
        user = (form.get("username", [""])[0] or form.get("user", [""])[0]
                or form.get("login", [""])[0] or "").lower()
        pwd = (form.get("password", [""])[0] or form.get("pass", [""])[0] or "").lower()
        if (user, pwd) in DEFAULT_CRED_PAIRS:
            return Classification("default_creds", 2,
                                  f"default credential pair: {user}/{pwd}")
        if user or pwd:
            return Classification("brute_force", 1,
                                  f"login attempt user={user!r}")

    # scanner detection from user agent
    if cfg.get("enable_scanner", True):
        m = _match_any(SCANNER_USER_AGENTS, ua)
        if m:
            return Classification("scanner", 1, f"scanner UA: {m}")

    # noisy enumerative paths
    if any(seg in path for seg in (
        "/wp-admin", "/phpmyadmin", "/.git", "/.svn", "/server-status",
        "/cgi-bin", "/admin/", "/manager/html", "/actuator/",
    )):
        return Classification("recon", 1, f"recon path: {path}")

    return Classification("benign", 0, "no signature matched")


def fingerprint_tool(user_agent: str) -> Optional[str]:
    """Best-effort tool fingerprint from the user-agent string."""
    if not user_agent:
        return None
    ua = user_agent.lower()
    table: Tuple[Tuple[str, str], ...] = (
        ("nikto", "nikto"), ("sqlmap", "sqlmap"), ("nmap", "nmap"),
        ("masscan", "masscan"), ("zgrab", "zgrab"), ("gobuster", "gobuster"),
        ("dirbuster", "dirbuster"), ("dirb", "dirb"),
        ("feroxbuster", "feroxbuster"), ("wpscan", "wpscan"),
        ("python-requests", "python-requests"), ("curl/", "curl"),
        ("wget/", "wget"), ("go-http-client", "go-http"),
        ("shodan", "shodan"), ("censys", "censys"),
    )
    for needle, label in table:
        if needle in ua:
            return label
    return None
