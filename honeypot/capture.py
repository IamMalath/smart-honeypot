"""Capture pipeline: turn a Flask request into a stored, classified event."""
from __future__ import annotations

import json
import time
from typing import Any, Dict

from flask import Request

from analyzer import classifier as cls
from analyzer import mitre, sessions
from storage import db

# cap on stored body bytes - prevents a malicious upload from blowing up the DB
MAX_BODY_BYTES = 16 * 1024


def _safe_body(request: Request) -> str:
    try:
        raw = request.get_data(cache=True)
    except Exception:
        return ""
    if not raw:
        return ""
    if len(raw) > MAX_BODY_BYTES:
        raw = raw[:MAX_BODY_BYTES]
    try:
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return repr(raw)


def capture_request(
    request: Request,
    db_path: str,
    classifier_cfg: Dict[str, Any],
    session_idle_window: float,
) -> Dict[str, Any]:
    """Persist a single request, classify it, attach session + MITRE techniques.

    Returns the stored event dict (useful for tests / debugging).
    """
    ts = time.time()
    body = _safe_body(request)
    headers = {k: v for k, v in request.headers.items()}
    ua = headers.get("User-Agent", "")
    fingerprint = cls.fingerprint_tool(ua)

    pre_event = {
        "ts": ts,
        "service": "web",
        "source_ip": request.remote_addr or "0.0.0.0",
        "source_port": request.environ.get("REMOTE_PORT"),
        "method": request.method,
        "path": request.path,
        "query_string": request.query_string.decode("utf-8", errors="replace"),
        "headers_json": json.dumps(headers, ensure_ascii=False),
        "body": body,
        "user_agent": ua,
        "fingerprint": fingerprint,
        "category": None,
        "severity": 0,
        "session_id": None,
    }

    # classify before insert so the event row is complete
    classification = cls.classify(pre_event, classifier_cfg)
    pre_event["category"] = classification.category
    pre_event["severity"] = classification.severity

    # session assignment
    session_id = sessions.assign_session(
        db_path, pre_event["source_ip"], ts, session_idle_window, fingerprint
    )
    pre_event["session_id"] = session_id

    event_id = db.insert_event(db_path, pre_event)

    # MITRE technique hits
    techs = mitre.techniques_for(classification.category)
    if techs:
        db.insert_technique_hits(db_path, event_id, session_id, techs, ts)

    pre_event["id"] = event_id
    pre_event["matched_rule"] = classification.matched_rule
    return pre_event
