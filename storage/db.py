"""SQLite storage layer for the smart honeypot.

Schema
------
events           one row per captured request (any service)
sessions         one row per attacker session (source_ip + idle window)
technique_hits   one row per (event, MITRE technique) pair
"""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from typing import Any, Dict, Iterable, List, Optional, Tuple

# A single module-level lock keeps writes serialised even when Flask is in
# threaded mode. SQLite handles concurrent reads natively but a write lock
# keeps the schema simple for a coursework prototype.
_WRITE_LOCK = threading.Lock()


SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              REAL    NOT NULL,         -- unix epoch seconds
    service         TEXT    NOT NULL,         -- "web", future: "ssh", "smb"
    source_ip       TEXT    NOT NULL,
    source_port     INTEGER,
    method          TEXT,
    path            TEXT,
    query_string    TEXT,
    headers_json    TEXT,                     -- JSON object of request headers
    body            TEXT,                     -- raw body (text-only, truncated)
    user_agent      TEXT,
    fingerprint     TEXT,                     -- "nikto", "sqlmap", "curl", ...
    category        TEXT,                     -- attack category (sqli, xss, ...)
    severity        INTEGER DEFAULT 0,        -- 0..3
    session_id      INTEGER,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);
CREATE INDEX IF NOT EXISTS idx_events_ts        ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_category  ON events(category);
CREATE INDEX IF NOT EXISTS idx_events_session   ON events(session_id);

CREATE TABLE IF NOT EXISTS sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip   TEXT    NOT NULL,
    started_at  REAL    NOT NULL,
    last_seen   REAL    NOT NULL,
    event_count INTEGER NOT NULL DEFAULT 0,
    fingerprint TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_source ON sessions(source_ip);
CREATE INDEX IF NOT EXISTS idx_sessions_last   ON sessions(last_seen);

CREATE TABLE IF NOT EXISTS technique_hits (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id      INTEGER NOT NULL,
    session_id    INTEGER,
    technique_id  TEXT    NOT NULL,           -- e.g. "T1190"
    technique_name TEXT,
    tactic        TEXT,
    ts            REAL    NOT NULL,
    FOREIGN KEY (event_id)   REFERENCES events(id),
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);
CREATE INDEX IF NOT EXISTS idx_hits_session ON technique_hits(session_id);
CREATE INDEX IF NOT EXISTS idx_hits_tech    ON technique_hits(technique_id);
"""


def init_db(db_path: str) -> None:
    """Create tables if they don't already exist."""
    with sqlite3.connect(db_path) as conn:
        conn.executescript(SCHEMA)
        conn.commit()


@contextmanager
def connect(db_path: str):
    """Context manager that yields a row-factory connection."""
    conn = sqlite3.connect(db_path, timeout=5.0)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


# ----- Writes -----------------------------------------------------------------

def insert_event(db_path: str, event: Dict[str, Any]) -> int:
    """Insert a captured request, return its event id."""
    cols = (
        "ts", "service", "source_ip", "source_port", "method", "path",
        "query_string", "headers_json", "body", "user_agent",
        "fingerprint", "category", "severity", "session_id",
    )
    values = tuple(event.get(c) for c in cols)
    with _WRITE_LOCK, connect(db_path) as conn:
        cur = conn.execute(
            f"INSERT INTO events ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
            values,
        )
        conn.commit()
        return int(cur.lastrowid)


def insert_technique_hits(
    db_path: str,
    event_id: int,
    session_id: Optional[int],
    techniques: Iterable[Dict[str, str]],
    ts: float,
) -> None:
    rows = [
        (event_id, session_id, t["id"], t.get("name"), t.get("tactic"), ts)
        for t in techniques
    ]
    if not rows:
        return
    with _WRITE_LOCK, connect(db_path) as conn:
        conn.executemany(
            "INSERT INTO technique_hits "
            "(event_id, session_id, technique_id, technique_name, tactic, ts) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            rows,
        )
        conn.commit()


def upsert_session(
    db_path: str,
    source_ip: str,
    ts: float,
    idle_window: float,
    fingerprint: Optional[str],
) -> int:
    """Find or create the active session for ``source_ip`` and bump its counters."""
    with _WRITE_LOCK, connect(db_path) as conn:
        row = conn.execute(
            "SELECT id, last_seen FROM sessions "
            "WHERE source_ip = ? ORDER BY last_seen DESC LIMIT 1",
            (source_ip,),
        ).fetchone()

        if row and (ts - row["last_seen"]) <= idle_window:
            sid = int(row["id"])
            conn.execute(
                "UPDATE sessions SET last_seen = ?, event_count = event_count + 1, "
                "fingerprint = COALESCE(fingerprint, ?) WHERE id = ?",
                (ts, fingerprint, sid),
            )
        else:
            cur = conn.execute(
                "INSERT INTO sessions (source_ip, started_at, last_seen, "
                "event_count, fingerprint) VALUES (?, ?, ?, 1, ?)",
                (source_ip, ts, ts, fingerprint),
            )
            sid = int(cur.lastrowid)
        conn.commit()
        return sid


def attach_session_to_event(db_path: str, event_id: int, session_id: int) -> None:
    with _WRITE_LOCK, connect(db_path) as conn:
        conn.execute(
            "UPDATE events SET session_id = ? WHERE id = ?",
            (session_id, event_id),
        )
        conn.commit()


# ----- Reads ------------------------------------------------------------------

def overview_stats(db_path: str) -> Dict[str, Any]:
    with connect(db_path) as conn:
        total_events = conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"]
        unique_attackers = conn.execute(
            "SELECT COUNT(DISTINCT source_ip) AS c FROM events"
        ).fetchone()["c"]
        sessions = conn.execute("SELECT COUNT(*) AS c FROM sessions").fetchone()["c"]

        top_categories = [
            dict(r) for r in conn.execute(
                "SELECT category, COUNT(*) AS c FROM events "
                "WHERE category IS NOT NULL AND category <> 'benign' "
                "GROUP BY category ORDER BY c DESC LIMIT 10"
            ).fetchall()
        ]
        top_techniques = [
            dict(r) for r in conn.execute(
                "SELECT technique_id, technique_name, tactic, COUNT(*) AS c "
                "FROM technique_hits GROUP BY technique_id "
                "ORDER BY c DESC LIMIT 10"
            ).fetchall()
        ]
        top_attackers = [
            dict(r) for r in conn.execute(
                "SELECT source_ip, COUNT(*) AS c FROM events "
                "GROUP BY source_ip ORDER BY c DESC LIMIT 10"
            ).fetchall()
        ]
    return {
        "total_events": total_events,
        "unique_attackers": unique_attackers,
        "sessions": sessions,
        "top_categories": top_categories,
        "top_techniques": top_techniques,
        "top_attackers": top_attackers,
    }


def list_sessions(db_path: str, limit: int = 100) -> List[Dict[str, Any]]:
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT s.id, s.source_ip, s.started_at, s.last_seen, "
            "       s.event_count, s.fingerprint, "
            "       (SELECT COUNT(DISTINCT technique_id) FROM technique_hits "
            "        WHERE session_id = s.id) AS distinct_techniques "
            "FROM sessions s "
            "ORDER BY s.last_seen DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_session(db_path: str, session_id: int) -> Optional[Dict[str, Any]]:
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM sessions WHERE id = ?", (session_id,)
        ).fetchone()
        if not row:
            return None
        events = [dict(e) for e in conn.execute(
            "SELECT id, ts, method, path, query_string, body, user_agent, "
            "       fingerprint, category, severity "
            "FROM events WHERE session_id = ? ORDER BY ts ASC",
            (session_id,),
        ).fetchall()]

        # parse stored headers JSON for display
        for e in events:
            try:
                hdrs = conn.execute(
                    "SELECT headers_json FROM events WHERE id = ?", (e["id"],)
                ).fetchone()
                e["headers"] = json.loads(hdrs["headers_json"]) if hdrs and hdrs["headers_json"] else {}
            except Exception:
                e["headers"] = {}

        techniques = [dict(t) for t in conn.execute(
            "SELECT technique_id, technique_name, tactic, COUNT(*) AS c "
            "FROM technique_hits WHERE session_id = ? "
            "GROUP BY technique_id ORDER BY c DESC",
            (session_id,),
        ).fetchall()]

        per_event_techniques: Dict[int, List[Dict[str, Any]]] = {}
        for r in conn.execute(
            "SELECT event_id, technique_id, technique_name, tactic "
            "FROM technique_hits WHERE session_id = ?",
            (session_id,),
        ).fetchall():
            per_event_techniques.setdefault(int(r["event_id"]), []).append(dict(r))

        for e in events:
            e["techniques"] = per_event_techniques.get(int(e["id"]), [])

    return {
        "session": dict(row),
        "events": events,
        "techniques": techniques,
    }


def events_per_minute(db_path: str, minutes: int = 60) -> List[Tuple[int, int]]:
    """Return [(minute_bucket_offset, count), ...] for the last ``minutes``."""
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT CAST(ts / 60 AS INTEGER) AS bucket, COUNT(*) AS c "
            "FROM events WHERE ts >= (strftime('%s','now') - ?) "
            "GROUP BY bucket ORDER BY bucket",
            (minutes * 60,),
        ).fetchall()
    return [(int(r["bucket"]), int(r["c"])) for r in rows]
