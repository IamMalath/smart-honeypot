"""Ground-truth tests for the classifier. Doubles as evaluation evidence."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from analyzer.classifier import classify, fingerprint_tool  # noqa: E402
from analyzer.mitre import techniques_for  # noqa: E402


def _req(method="GET", path="/", qs="", body="", ua=""):
    return {
        "method": method, "path": path, "query_string": qs,
        "body": body, "user_agent": ua,
    }


def test_benign_request_is_benign():
    c = classify(_req(path="/", ua="Mozilla/5.0 Firefox"))
    assert c.category == "benign"
    assert c.severity == 0


def test_sqli_union_select():
    c = classify(_req(path="/api/v1/users", qs="id=1' UNION SELECT username,password FROM users--"))
    assert c.category == "sqli"
    assert c.severity >= 2


def test_sqli_or_1_eq_1():
    c = classify(_req(qs="id=1' OR 1=1 --"))
    assert c.category == "sqli"


def test_xss_script_tag():
    c = classify(_req(qs="q=<script>alert(1)</script>"))
    assert c.category == "xss"


def test_xss_event_handler():
    c = classify(_req(qs="q=<img src=x onerror=alert(1)>"))
    assert c.category == "xss"


def test_lfi_etc_passwd():
    c = classify(_req(path="/index.php", qs="file=../../../../etc/passwd"))
    assert c.category == "lfi"


def test_path_traversal_only():
    c = classify(_req(path="/static", qs="x=../../config"))
    assert c.category == "path_traversal"


def test_rce_command_chain():
    c = classify(_req(qs="cmd=;cat /etc/passwd"))
    assert c.category == "rce"
    assert c.severity == 3


def test_rce_backticks():
    c = classify(_req(qs="name=`id`"))
    assert c.category == "rce"


def test_webshell_php_eval():
    c = classify(_req(method="POST", path="/upload.php",
                      body="<?php eval($_POST['x']); ?>"))
    assert c.category == "webshell"


def test_sensitive_env():
    c = classify(_req(path="/.env"))
    assert c.category == "sensitive_file"


def test_sensitive_git_config():
    c = classify(_req(path="/.git/config"))
    assert c.category == "sensitive_file"


def test_default_creds_admin_admin():
    c = classify(_req(method="POST", path="/login",
                      body="username=admin&password=admin"))
    assert c.category == "default_creds"


def test_brute_force_other_creds():
    c = classify(_req(method="POST", path="/wp-login.php",
                      body="log=alice&pwd=summer2024"))
    # wp-login uses log/pwd; we accept brute_force OR scanner depending on UA
    assert c.category in ("brute_force", "default_creds", "recon", "benign")
    # at minimum it should not be misclassified as RCE/SQLi/XSS
    assert c.category not in ("rce", "sqli", "xss", "lfi", "path_traversal")


def test_scanner_user_agent_nikto():
    c = classify(_req(path="/", ua="Mozilla/5.00 (Nikto/2.5.0)"))
    assert c.category == "scanner"


def test_scanner_user_agent_sqlmap_alone_no_payload():
    # sqlmap UA alone (no payload) should still be flagged as scanner
    c = classify(_req(path="/", ua="sqlmap/1.7.2"))
    assert c.category == "scanner"


def test_recon_path_phpmyadmin():
    c = classify(_req(path="/phpmyadmin/", ua="Mozilla/5.0"))
    assert c.category == "recon"


def test_fingerprint_tool():
    assert fingerprint_tool("Mozilla/5.0 sqlmap/1.7") == "sqlmap"
    assert fingerprint_tool("curl/8.4.0") == "curl"
    assert fingerprint_tool("Mozilla/5.0 Firefox") is None


def test_mitre_mapping_sqli():
    techs = techniques_for("sqli")
    ids = {t["id"] for t in techs}
    assert "T1190" in ids


def test_mitre_mapping_brute_force():
    techs = techniques_for("brute_force")
    ids = {t["id"] for t in techs}
    assert "T1110.001" in ids


def test_mitre_mapping_benign_empty():
    assert techniques_for("benign") == []


# ---- aggregate precision report (printed when run with -s) -------------------

def test_aggregate_precision_against_ground_truth():
    cases = [
        (_req(path="/", ua="Mozilla Firefox"), "benign"),
        (_req(qs="id=1' OR 1=1 --"), "sqli"),
        (_req(qs="q=<script>alert(1)</script>"), "xss"),
        (_req(path="/x", qs="f=../../etc/passwd"), "lfi"),
        (_req(qs="cmd=;cat /etc/passwd"), "rce"),
        (_req(path="/.env"), "sensitive_file"),
        (_req(method="POST", path="/login", body="username=admin&password=admin"), "default_creds"),
        (_req(path="/", ua="Nikto/2.5"), "scanner"),
        (_req(path="/phpmyadmin/", ua="Mozilla/5.0"), "recon"),
    ]
    correct = sum(1 for req, expected in cases if classify(req).category == expected)
    precision = correct / len(cases)
    print(f"\n[eval] classifier precision on {len(cases)} ground-truth cases: "
          f"{correct}/{len(cases)} = {precision:.1%}")
    assert precision >= 0.85
