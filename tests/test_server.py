import json
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
pytest.importorskip("flask")

from hifiberry_auth.store import AuthStore
from hifiberry_auth.manifests import TierMap
from hifiberry_auth.server import create_app

COOKIE = "hifiberry_session"

MANIFEST = {
    "service": "config", "match_prefix": "/api/config/v1", "default_tier": "risky",
    "rules": [
        {"tier": "ok", "methods": ["GET"], "paths": ["/version"]},
        {"tier": "ok", "methods": ["POST"], "paths": ["/systemd/service/*/*"]},
        {"tier": "risky", "methods": ["*"], "paths": ["/**"]},
    ],
}


def _client(tmp_path, protection="unset", with_password=False):
    d = tmp_path / "auth.d"; d.mkdir()
    (d / "config.json").write_text(json.dumps(MANIFEST))
    store = AuthStore(db_path=str(tmp_path / "auth.db"))
    if with_password:
        store.set_password("secret")
    store.set_protection(protection)
    tm = TierMap(str(d)).load()
    app = create_app(store, tm)
    app.testing = True
    return app.test_client(), store


def _verify(client, method, uri, cookie=None, csrf=None):
    headers = {"X-Original-Method": method, "X-Original-URI": uri}
    if csrf:
        headers["X-CSRF-Token"] = csrf
    if cookie:
        client.set_cookie(COOKIE, cookie, domain="localhost")
    return client.get("/_auth/verify", headers=headers)


def _login(client, pw="secret"):
    r = client.post("/api/auth/login", json={"password": pw})
    body = r.get_json()
    # extract the session cookie the app set
    cookie = None
    for h in r.headers.getlist("Set-Cookie"):
        if h.startswith(COOKIE + "="):
            cookie = h.split(";", 1)[0].split("=", 1)[1]
    return r, cookie, (body or {}).get("csrf")


# --- verify matrix ----------------------------------------------------------

def test_ok_tier_always_allows(tmp_path):
    client, _ = _client(tmp_path, protection="unset")
    assert _verify(client, "GET", "/api/config/v1/version").status_code == 200


def test_risky_unset_prompts_set_password(tmp_path):
    client, _ = _client(tmp_path, protection="unset")
    r = _verify(client, "POST", "/api/config/v1/system/reboot")
    assert r.status_code == 401
    assert r.headers.get("WWW-Authenticate-Hint") == "set-password"


def test_risky_off_allows(tmp_path):
    client, _ = _client(tmp_path, protection="off")
    assert _verify(client, "POST", "/api/config/v1/system/reboot").status_code == 200


def test_risky_protected_without_session_prompts_login(tmp_path):
    client, _ = _client(tmp_path, protection="risky", with_password=True)
    r = _verify(client, "POST", "/api/config/v1/system/reboot")
    assert r.status_code == 401
    assert r.headers.get("WWW-Authenticate-Hint") == "login"


def test_risky_get_with_session_allows(tmp_path):
    client, _ = _client(tmp_path, protection="risky", with_password=True)
    _, cookie, _ = _login(client)
    assert _verify(client, "GET", "/api/config/v1/some-read", cookie=cookie).status_code == 200


def test_risky_post_requires_matching_csrf(tmp_path):
    client, _ = _client(tmp_path, protection="risky", with_password=True)
    _, cookie, csrf = _login(client)
    # POST without csrf -> 401
    assert _verify(client, "POST", "/api/config/v1/system/reboot", cookie=cookie).status_code == 401
    # POST with wrong csrf -> 401
    assert _verify(client, "POST", "/api/config/v1/system/reboot", cookie=cookie, csrf="nope").status_code == 401
    # POST with the right csrf -> 200
    assert _verify(client, "POST", "/api/config/v1/system/reboot", cookie=cookie, csrf=csrf).status_code == 200


def test_protection_all_gates_ok_tier_too(tmp_path):
    client, _ = _client(tmp_path, protection="all", with_password=True)
    assert _verify(client, "GET", "/api/config/v1/version").status_code == 401
    _, cookie, _ = _login(client)
    assert _verify(client, "GET", "/api/config/v1/version", cookie=cookie).status_code == 200


# --- auth endpoints ---------------------------------------------------------

def test_set_password_mints_session_and_sets_protection(tmp_path):
    client, store = _client(tmp_path, protection="unset")
    r = client.post("/api/auth/set-password", json={"password": "newpass"})
    assert r.status_code == 200
    assert store.has_password() is True
    assert store.get_protection() == "risky"
    assert r.get_json().get("csrf")
    assert any(h.startswith(COOKIE + "=") for h in r.headers.getlist("Set-Cookie"))


def test_change_password_requires_current(tmp_path):
    client, _ = _client(tmp_path, protection="risky", with_password=True)
    assert client.post("/api/auth/set-password", json={"password": "x"}).status_code == 401
    assert client.post("/api/auth/set-password",
                       json={"password": "x", "current": "wrong"}).status_code == 401
    assert client.post("/api/auth/set-password",
                       json={"password": "x", "current": "secret"}).status_code == 200


def test_login_wrong_password_401(tmp_path):
    client, _ = _client(tmp_path, protection="risky", with_password=True)
    assert client.post("/api/auth/login", json={"password": "wrong"}).status_code == 401


def test_login_rate_limited_after_failures(tmp_path):
    client, _ = _client(tmp_path, protection="risky", with_password=True)
    for _ in range(5):
        client.post("/api/auth/login", json={"password": "wrong"})
    # further attempts are throttled (429) even with the right password
    assert client.post("/api/auth/login", json={"password": "secret"}).status_code == 429


def test_status_shape(tmp_path):
    client, _ = _client(tmp_path, protection="unset")
    body = client.get("/api/auth/status").get_json()
    assert body["protection"] == "unset"
    assert body["has_password"] is False
    assert body["authenticated"] is False


def test_policy_requires_session(tmp_path):
    client, store = _client(tmp_path, protection="risky", with_password=True)
    assert client.post("/api/auth/policy", json={"protection": "all"}).status_code == 401
    _, cookie, csrf = _login(client)
    client.set_cookie(COOKIE, cookie, domain="localhost")
    r = client.post("/api/auth/policy", json={"protection": "all"},
                    headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200
    assert store.get_protection() == "all"


def test_logout_clears_the_cookie(tmp_path):
    client, _ = _client(tmp_path, protection="risky", with_password=True)
    r = client.post("/api/auth/logout")
    assert r.status_code == 200
    # a cleared cookie (empty / expired) is set
    assert any(h.startswith(COOKIE + "=") for h in r.headers.getlist("Set-Cookie"))


def test_a_deleted_row_invalidates_the_cookie(tmp_path):
    client, store = _client(tmp_path, protection="risky", with_password=True)
    _, cookie, _ = _login(client)
    assert _verify(client, "GET", "/api/config/v1/some-read", cookie=cookie).status_code == 200

    store.remove_all_sessions()

    assert _verify(client, "GET", "/api/config/v1/some-read", cookie=cookie).status_code == 401
    client.set_cookie(COOKIE, cookie, domain="localhost")
    assert client.get("/api/auth/csrf").status_code == 401
    assert client.get("/api/auth/status").get_json()["authenticated"] is False


def test_login_records_a_session_row(tmp_path):
    client, store = _client(tmp_path, protection="risky", with_password=True)
    _login(client)
    with store._conn() as c:
        assert c.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1
