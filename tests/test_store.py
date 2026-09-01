import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from hifiberry_auth.store import AuthStore


def _store(tmp_path):
    return AuthStore(db_path=str(tmp_path / "auth.db"))


def test_no_password_initially(tmp_path):
    s = _store(tmp_path)
    assert s.has_password() is False
    assert s.verify_password("anything") is False


def test_set_then_verify_password(tmp_path):
    s = _store(tmp_path)
    s.set_password("s3cret-pass")
    assert s.has_password() is True
    assert s.verify_password("s3cret-pass") is True
    assert s.verify_password("wrong") is False


def test_password_is_hashed_not_stored_plaintext(tmp_path):
    s = _store(tmp_path)
    s.set_password("plaintext-here")
    raw = open(tmp_path / "auth.db", "rb").read()
    assert b"plaintext-here" not in raw
    assert b"argon2" in raw or b"$argon2" in raw


def test_change_password(tmp_path):
    s = _store(tmp_path)
    s.set_password("first")
    s.set_password("second")
    assert s.verify_password("first") is False
    assert s.verify_password("second") is True


def test_signing_key_is_generated_and_stable(tmp_path):
    s = _store(tmp_path)
    k1 = s.get_signing_key()
    assert isinstance(k1, bytes) and len(k1) >= 32
    assert s.get_signing_key() == k1               # stable within instance
    assert AuthStore(db_path=str(tmp_path / "auth.db")).get_signing_key() == k1  # persisted


def test_protection_defaults_unset_and_persists(tmp_path):
    s = _store(tmp_path)
    assert s.get_protection() == "unset"
    s.set_protection("risky")
    assert s.get_protection() == "risky"
    assert _store(tmp_path).get_protection() == "risky"


def test_protection_rejects_bad_values(tmp_path):
    s = _store(tmp_path)
    with pytest.raises(ValueError):
        s.set_protection("banana")


def test_sessions_start_empty_and_round_trip(tmp_path):
    s = _store(tmp_path)
    assert s.session_is_active("nope") is False
    s.add_session("sid-a", exp=2_000_000_000)
    assert s.session_is_active("sid-a") is True


def test_remove_session_only_removes_that_one(tmp_path):
    s = _store(tmp_path)
    s.add_session("sid-a", exp=2_000_000_000)
    s.add_session("sid-b", exp=2_000_000_000)
    s.remove_session("sid-a")
    assert s.session_is_active("sid-a") is False
    assert s.session_is_active("sid-b") is True


def test_remove_all_sessions(tmp_path):
    s = _store(tmp_path)
    s.add_session("sid-a", exp=2_000_000_000)
    s.add_session("sid-b", exp=2_000_000_000)
    s.remove_all_sessions()
    assert s.session_is_active("sid-a") is False
    assert s.session_is_active("sid-b") is False


def test_prune_removes_only_expired_rows(tmp_path):
    s = _store(tmp_path)
    s.add_session("stale", exp=1_000)
    s.add_session("fresh", exp=2_000_000_000)
    assert s.prune_sessions(now=1_500) == 1
    assert s.session_is_active("stale") is False
    assert s.session_is_active("fresh") is True


def test_sessions_persist_across_instances(tmp_path):
    s = _store(tmp_path)
    s.add_session("sid-a", exp=2_000_000_000)
    assert _store(tmp_path).session_is_active("sid-a") is True


def test_empty_sid_is_never_active(tmp_path):
    s = _store(tmp_path)
    assert s.session_is_active("") is False
    assert s.session_is_active(None) is False
