"""Sessionisation: thin wrapper around storage.db so the honeypot pipeline
doesn't need to know SQL details."""
from __future__ import annotations

from typing import Optional

from storage import db


def assign_session(
    db_path: str,
    source_ip: str,
    ts: float,
    idle_window: float,
    fingerprint: Optional[str],
) -> int:
    """Return the session id this event belongs to (creates one if needed)."""
    return db.upsert_session(db_path, source_ip, ts, idle_window, fingerprint)
