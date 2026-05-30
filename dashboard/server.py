"""Analyst dashboard - read-only views over the honeypot DB."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

from flask import Flask, abort, render_template

from storage import db


def _fmt_ts(value: float) -> str:
    if value is None:
        return ""
    return datetime.fromtimestamp(float(value), tz=timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )


def create_dashboard_app(cfg: Dict[str, Any], db_path: str) -> Flask:
    app = Flask(__name__)
    app.jinja_env.filters["ts"] = _fmt_ts

    @app.route("/")
    def overview():  # noqa: ANN202
        stats = db.overview_stats(db_path)
        epm = db.events_per_minute(db_path, minutes=60)
        return render_template("overview.html", stats=stats, events_per_minute=epm)

    @app.route("/sessions")
    def sessions_view():  # noqa: ANN202
        sess = db.list_sessions(db_path, limit=200)
        return render_template("sessions.html", sessions=sess)

    @app.route("/sessions/<int:session_id>")
    def session_detail(session_id: int):  # noqa: ANN202
        data = db.get_session(db_path, session_id)
        if data is None:
            abort(404)
        return render_template("session_detail.html", **data)

    @app.template_filter("severity_badge")
    def severity_badge(sev: int) -> str:
        sev = int(sev or 0)
        labels = {0: "info", 1: "low", 2: "med", 3: "high"}
        colors = {0: "#5c6370", 1: "#3a8fbd", 2: "#d09f3a", 3: "#c0392b"}
        return (
            f'<span style="background:{colors[sev]};color:#fff;padding:2px 8px;'
            f'border-radius:10px;font-size:11px">{labels[sev]}</span>'
        )

    return app
