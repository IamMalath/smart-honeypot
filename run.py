"""Entry point: launches the honeypot and the analyst dashboard together."""
from __future__ import annotations

import os
import sys
import threading
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from honeypot.server import create_honeypot_app  # noqa: E402
from dashboard.server import create_dashboard_app  # noqa: E402
from storage.db import init_db  # noqa: E402


def load_config() -> dict:
    with open(ROOT / "config.yaml", "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _serve(app, host: str, port: int, label: str) -> None:
    print(f"[{label}] listening on http://{host}:{port}")
    # Use Flask's built-in server. For coursework demo this is fine; behind a
    # reverse proxy in production you'd swap for gunicorn/uwsgi.
    app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)


def main() -> None:
    cfg = load_config()
    db_path = ROOT / cfg["storage"]["db_path"]
    db_path.parent.mkdir(parents=True, exist_ok=True)
    init_db(str(db_path))

    honeypot_app = create_honeypot_app(cfg, str(db_path))
    dashboard_app = create_dashboard_app(cfg, str(db_path))

    t = threading.Thread(
        target=_serve,
        args=(honeypot_app, cfg["honeypot"]["host"], cfg["honeypot"]["port"], "honeypot"),
        daemon=True,
    )
    t.start()
    _serve(dashboard_app, cfg["dashboard"]["host"], cfg["dashboard"]["port"], "dashboard")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nShutting down.")
        sys.exit(0)
