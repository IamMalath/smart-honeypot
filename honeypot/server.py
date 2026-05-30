"""The honeypot Flask app: serves attractive bait routes and captures every hit."""
from __future__ import annotations

from typing import Any, Dict

from flask import Flask, Response, request

from honeypot import responses
from honeypot.capture import capture_request


def _serve(body: str, status: int = 200, content_type: str = "text/html; charset=utf-8",
           banner: str = "Apache/2.4.41 (Ubuntu)") -> Response:
    resp = Response(body, status=status, mimetype=content_type)
    resp.headers["Server"] = banner
    return resp


def create_honeypot_app(cfg: Dict[str, Any], db_path: str) -> Flask:
    app = Flask(__name__)
    classifier_cfg = cfg.get("classifier", {})
    session_idle_window = float(cfg.get("session", {}).get("idle_window_seconds", 600))
    banner = cfg.get("honeypot", {}).get("banner", "Apache/2.4.41 (Ubuntu)")

    @app.before_request
    def _capture():  # noqa: ANN202
        # Capture every incoming request *before* the route handler runs.
        # Failures here must never break the honeypot.
        try:
            event = capture_request(request, db_path, classifier_cfg, session_idle_window)
            print(
                f"[honeypot] {event['source_ip']} {event['method']} {event['path']} "
                f"-> category={event['category']} sev={event['severity']} "
                f"rule={event.get('matched_rule')!r}"
            )
        except Exception as exc:  # pragma: no cover - defensive
            print(f"[honeypot] capture error: {exc}")

    # ---- bait routes -------------------------------------------------------

    @app.route("/", methods=["GET"])
    def root():  # noqa: ANN202
        return _serve(responses.FAKE_INDEX, banner=banner)

    @app.route("/robots.txt")
    def robots():  # noqa: ANN202
        return _serve(responses.FAKE_ROBOTS, content_type="text/plain", banner=banner)

    # generic login form
    @app.route("/login", methods=["GET", "POST"])
    @app.route("/admin", methods=["GET", "POST"])
    @app.route("/admin/login", methods=["GET", "POST"])
    @app.route("/administrator", methods=["GET", "POST"])
    @app.route("/manager/html", methods=["GET", "POST"])
    @app.route("/user/login", methods=["GET", "POST"])
    def login():  # noqa: ANN202
        if request.method == "POST":
            # Always fail. Slight delay would be more believable but we keep
            # the prototype responsive for the simulator.
            return _serve(responses.FAKE_LOGIN_FAIL_HTML, status=401, banner=banner)
        return _serve(responses.FAKE_LOGIN_HTML, banner=banner)

    @app.route("/wp-login.php", methods=["GET", "POST"])
    def wp_login():  # noqa: ANN202
        if request.method == "POST":
            return _serve(responses.FAKE_WP_LOGIN, status=401, banner=banner)
        return _serve(responses.FAKE_WP_LOGIN, banner=banner)

    @app.route("/phpmyadmin/", methods=["GET", "POST"])
    @app.route("/phpmyadmin/index.php", methods=["GET", "POST"])
    @app.route("/pma/", methods=["GET", "POST"])
    def phpmyadmin():  # noqa: ANN202
        if request.method == "POST":
            return _serve(responses.FAKE_PHPMYADMIN, status=401, banner=banner)
        return _serve(responses.FAKE_PHPMYADMIN, banner=banner)

    @app.route("/.env")
    def fake_env():  # noqa: ANN202
        return _serve(responses.FAKE_ENV, content_type="text/plain", banner=banner)

    @app.route("/.git/config")
    def fake_git_config():  # noqa: ANN202
        return _serve(responses.FAKE_GIT_CONFIG, content_type="text/plain", banner=banner)

    @app.route("/wp-config.php")
    def fake_wp_config():  # noqa: ANN202
        # serving as text/plain so attackers see "leaked" PHP source
        body = "<?php\n$db_pass = 'hunter2';\n$db_user = 'wpuser';\n"
        return _serve(body, content_type="text/plain", banner=banner)

    @app.route("/api/v1/status")
    def api_status():  # noqa: ANN202
        return _serve(
            responses.FAKE_API_STATUS,
            content_type="application/json",
            banner=banner,
        )

    @app.route("/api/v1/users")
    @app.route("/api/v1/users/<path:_>")
    def api_users(_=None):  # noqa: ANN202
        # Returns a fake-looking enumeration payload to encourage further probing.
        body = (
            '{"users":[{"id":1,"name":"alice"},{"id":2,"name":"bob"},'
            '{"id":3,"name":"charlie"}]}'
        )
        return _serve(body, content_type="application/json", banner=banner)

    @app.route("/server-status")
    def server_status():  # noqa: ANN202
        return _serve("Apache Server Status — restricted", status=403, banner=banner)

    @app.errorhandler(404)
    def not_found(_):  # noqa: ANN202
        return _serve(responses.FAKE_404, status=404, banner=banner)

    @app.errorhandler(500)
    def server_error(_):  # noqa: ANN202
        return _serve(responses.FAKE_500, status=500, banner=banner)

    # generic catch-all so traversal/LFI attempts get realistic 404s and still
    # get captured by the @before_request hook.
    @app.route("/<path:any_path>", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"])
    def catch_all(any_path: str):  # noqa: ANN202, ARG001
        return _serve(responses.FAKE_404, status=404, banner=banner)

    return app
