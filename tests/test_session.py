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
    cookie, csrf = s.mint()
    data = s.verify(cookie)
    assert data is not None
    assert data["csrf"] == csrf


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
    cookie, csrf = s.mint()
    assert s.verify(cookie)["csrf"] == csrf
    # two mints get distinct csrf tokens
    _, csrf2 = s.mint()
    assert csrf2 != csrf
