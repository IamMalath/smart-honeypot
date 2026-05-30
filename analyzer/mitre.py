"""Map internal attack categories to MITRE ATT&CK techniques."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

_DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "mitre_techniques.json"

with open(_DATA_PATH, "r", encoding="utf-8") as fh:
    TECHNIQUES: Dict[str, Dict[str, str]] = json.load(fh)


# Each category produced by the classifier maps to one or more ATT&CK techniques.
CATEGORY_TO_TECHNIQUES: Dict[str, List[str]] = {
    "scanner":         ["T1595.002"],
    "recon":           ["T1595.002", "T1018"],
    "brute_force":     ["T1110.001"],
    "default_creds":   ["T1078.001", "T1110.001"],
    "sqli":            ["T1190"],
    "xss":             ["T1059.007"],
    "lfi":             ["T1083"],
    "path_traversal":  ["T1083"],
    "rce":             ["T1059", "T1059.004", "T1190"],
    "webshell":        ["T1505.003", "T1059.004"],
    "sensitive_file":  ["T1552.001"],
    # benign requests intentionally produce no technique hits
    "benign":          [],
}


def techniques_for(category: str) -> List[Dict[str, str]]:
    """Resolve a category to a list of {id, name, tactic} dicts."""
    out: List[Dict[str, str]] = []
    for tid in CATEGORY_TO_TECHNIQUES.get(category, []):
        meta = TECHNIQUES.get(tid, {})
        out.append({
            "id": tid,
            "name": meta.get("name", tid),
            "tactic": meta.get("tactic", "Unknown"),
        })
    return out
