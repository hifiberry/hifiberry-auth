import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from hifiberry_auth.session import Session

KEY = b"test-signing-key-0123456789abcdef"


def _session(now=1000.0, **kw):
    clock = {"t": now}
    kw.setdefault("ttl_seconds", 100)
    kw.setdefault("remember_ttl_seconds", 1000)
    s = Session(KEY, clock=lambda: clock["t"], **kw)
    return s, clock


def test_mint_then_verify_round_trips():
    s, _ = _session()
    cookie, minted = s.mint()
    data = s.verify(cookie)
    assert data is not None
    assert data["csrf"] == minted["csrf"]
    assert data["sid"] == minted["sid"]


def test_tampered_cookie_fails():
    s, _ = _session()
    cookie, _ = s.mint()
    body, sig = cookie.rsplit(".", 1)
    tampered = body + "x." + sig
    assert s.verify(tampered) is None
    assert s.verify(body + "." + "AAAA") is None


def test_expired_cookie_fails():
    s, clock = _session(now=1000.0, ttl_seconds=100)
    cookie, _ = s.mint()
    clock["t"] = 1099.0
    assert s.verify(cookie) is not None  # just before expiry
    clock["t"] = 1100.0
    assert s.verify(cookie) is None      # at/after expiry


def test_remember_uses_longer_ttl():
    s, clock = _session(now=1000.0, ttl_seconds=100, remember_ttl_seconds=1000)
    cookie, _ = s.mint(remember=True)
    clock["t"] = 1500.0  # past the short ttl, within remember ttl
    assert s.verify(cookie) is not None


def test_a_different_key_rejects_the_cookie():
    s, _ = _session()
    cookie, _ = s.mint()
    other = Session(b"a-completely-different-key-99999999", clock=lambda: 1000.0)
    assert other.verify(cookie) is None


def test_garbage_input_is_rejected():
    s, _ = _session()
    for bad in ("", "nodot", "a.b.c.d", None, "....", "x." * 50):
        assert s.verify(bad) is None


def test_csrf_token_is_bound_in_the_cookie():
    s, _ = _session()
    cookie, minted = s.mint()
    assert s.verify(cookie)["csrf"] == minted["csrf"]
    # two mints get distinct csrf tokens
    _, minted2 = s.mint()
    assert minted2["csrf"] != minted["csrf"]


def test_each_mint_gets_a_distinct_sid():
    s, _ = _session()
    _, a = s.mint()
    _, b = s.mint()
    assert a["sid"] and b["sid"]
    assert a["sid"] != b["sid"]


def test_verify_returns_the_expiry_it_signed():
    s, _ = _session(now=1000.0, ttl_seconds=100)
    cookie, minted = s.mint()
    assert s.verify(cookie)["exp"] == minted["exp"] == 1100


def test_verify_rejects_a_correctly_signed_token_without_sid():
    """Cookies minted before this change carry no sid. They must stop
    verifying rather than become permanently unrevokable."""
    import base64, json
    s, _ = _session(now=1000.0)
    payload = {"v": 1, "iat": 1000, "exp": 1100, "csrf": "some-csrf-token"}
    body = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode()).rstrip(b"=").decode()
    old_style = f"{body}.{s._mac(body)}"
    assert s.verify(old_style) is None
