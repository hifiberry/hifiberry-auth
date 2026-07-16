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
