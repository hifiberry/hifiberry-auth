"""The hifiberry-auth HTTP surface: the nginx auth_request verify endpoint plus
the login / set-password / policy / status endpoints.

All logic maps a request's tier + the protection policy + the session to
allow (200) or deny (401), per the design's decision matrix.
"""

import hmac
import logging
import time

try:
    from flask import Flask, request, jsonify, make_response
except ImportError:  # allows import without Flask (e.g. partial test runs)
    Flask = None

from .session import Session

logger = logging.getLogger(__name__)

COOKIE_NAME = "hifiberry_session"
CSRF_HEADER = "X-CSRF-Token"
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")


class RateLimiter:
    def __init__(self, clock=time.time, max_fail=5, cooldown=30):
        self.clock = clock
        self.max_fail = max_fail
        self.cooldown = cooldown
        self._fails = 0
        self._locked_until = 0.0

    def blocked(self) -> bool:
        return self.clock() < self._locked_until

    def record_fail(self):
        self._fails += 1
        if self._fails >= self.max_fail:
            self._locked_until = self.clock() + self.cooldown
            self._fails = 0

    def record_success(self):
        self._fails = 0
        self._locked_until = 0.0


def decide(method, tier, protection, session, csrf_header):
    """Return (hint, status). hint is None on allow, else 'set-password'|'login'."""
    method = (method or "").upper()
    if tier == "ok" and protection != "all":
        return None, 200
    if tier == "risky" and protection == "off":
        return None, 200
    if tier == "risky" and protection == "unset":
        return "set-password", 401
    # need a valid session (risky+protected, or ok+protection==all)
    if session is None:
        return "login", 401
    if method not in SAFE_METHODS:
        if not csrf_header or not hmac.compare_digest(csrf_header, session["csrf"]):
            return "login", 401
    return None, 200


def create_app(store, tier_map, clock=time.time):
    app = Flask(__name__)
    sessions = Session(store.get_signing_key(), clock=clock)
    limiter = RateLimiter(clock=clock)

    def _current_session():
        payload = sessions.verify(request.cookies.get(COOKIE_NAME))
        if payload is None or not store.session_is_active(payload["sid"]):
            return None
        return payload

    def _set_cookie(resp, cookie_value, max_age):
        resp.set_cookie(COOKIE_NAME, cookie_value, max_age=max_age, httponly=True,
                        samesite="Lax", path="/")
        return resp

    def _authed_response(remember=False):
        cookie, session = sessions.mint(remember=remember)
        store.add_session(session["sid"], session["exp"])
        max_age = sessions.remember_ttl if remember else sessions.ttl
        resp = make_response(jsonify({"status": "success", "csrf": session["csrf"]}))
        return _set_cookie(resp, cookie, max_age)

    # -- nginx auth_request ---------------------------------------------

    @app.route("/_auth/verify")
    def verify():
        method = request.headers.get("X-Original-Method", "GET")
        uri = request.headers.get("X-Original-URI", "/")
        tier = tier_map.tier(method, uri)
        protection = store.get_protection()
        session = _current_session()
        csrf = request.headers.get(CSRF_HEADER)
        hint, status = decide(method, tier, protection, session, csrf)
        resp = make_response("", status)
        if hint:
            resp.headers["WWW-Authenticate-Hint"] = hint
        return resp

    # -- auth endpoints --------------------------------------------------

    @app.route("/api/auth/status")
    def status():
        return jsonify({
            "protection": store.get_protection(),
            "has_password": store.has_password(),
            "authenticated": _current_session() is not None,
        })

    @app.route("/api/auth/set-password", methods=["POST"])
    def set_password():
        body = request.get_json(silent=True) or {}
        new = body.get("password")
        if not new:
            return jsonify({"status": "error", "message": "password required"}), 400
        if store.has_password():
            if not store.verify_password(body.get("current", "")):
                return jsonify({"status": "error", "message": "current password required"}), 401
        store.set_password(new)
        store.remove_all_sessions()
        if store.get_protection() in ("unset", "off"):
            store.set_protection("risky")
        return _authed_response(remember=bool(body.get("remember")))

    @app.route("/api/auth/login", methods=["POST"])
    def login():
        if limiter.blocked():
            return jsonify({"status": "error", "message": "too many attempts, try later"}), 429
        body = request.get_json(silent=True) or {}
        if not store.verify_password(body.get("password", "")):
            limiter.record_fail()
            return jsonify({"status": "error", "message": "invalid password"}), 401
        limiter.record_success()
        store.prune_sessions(int(clock()))
        return _authed_response(remember=bool(body.get("remember")))

    @app.route("/api/auth/logout", methods=["POST"])
    def logout():
        session = _current_session()
        csrf_header = request.headers.get(CSRF_HEADER)
        ok = bool(session is not None and csrf_header
                  and hmac.compare_digest(csrf_header, session["csrf"]))
        if ok:
            store.remove_session(session["sid"])
        resp = make_response(
            jsonify({"status": "success"} if ok else
                    {"status": "error", "message": "authentication required"}),
            200 if ok else 401)
        resp.set_cookie(COOKIE_NAME, "", max_age=0, httponly=True,
                        samesite="Lax", path="/")
        return resp

    @app.route("/api/auth/policy", methods=["POST"])
    def policy():
        session = _current_session()
        if session is None:
            return jsonify({"status": "error", "message": "authentication required"}), 401
        body = request.get_json(silent=True) or {}
        value = body.get("protection")
        try:
            store.set_protection(value)
        except ValueError as e:
            return jsonify({"status": "error", "message": str(e)}), 400
        return jsonify({"status": "success", "protection": value})

    @app.route("/api/auth/csrf")
    def csrf():
        session = _current_session()
        if session is None:
            return jsonify({"status": "error"}), 401
        return jsonify({"csrf": session["csrf"]})

    return app
