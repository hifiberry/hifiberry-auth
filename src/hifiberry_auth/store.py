"""Persistent auth state: the device password (argon2id), the session signing
key, the protection policy, and a session allowlist — a small SQLite key/value
store and relational tables."""

import os
import secrets
import sqlite3
import threading
import time

from argon2 import PasswordHasher
from argon2.exceptions import Argon2Error

PROTECTION_VALUES = ("unset", "off", "risky", "all")


class AuthStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._hasher = PasswordHasher()
        parent = os.path.dirname(db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._init_db()

    def _conn(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        with self._lock, self._conn() as c:
            c.execute("CREATE TABLE IF NOT EXISTS auth_kv (key TEXT PRIMARY KEY, value TEXT)")
            c.execute("CREATE TABLE IF NOT EXISTS sessions ("
                      "sid TEXT PRIMARY KEY, "
                      "exp INTEGER NOT NULL, "
                      "created INTEGER NOT NULL)")

    def _get(self, key, default=None):
        with self._conn() as c:
            row = c.execute("SELECT value FROM auth_kv WHERE key=?", (key,)).fetchone()
        return row[0] if row else default

    def _set(self, key, value):
        with self._lock, self._conn() as c:
            c.execute("INSERT INTO auth_kv (key, value) VALUES (?, ?) "
                      "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    # -- password --------------------------------------------------------

    def has_password(self) -> bool:
        return self._get("password_hash") is not None

    def set_password(self, password: str) -> None:
        if not password:
            raise ValueError("password must not be empty")
        self._set("password_hash", self._hasher.hash(password))

    def verify_password(self, password: str) -> bool:
        stored = self._get("password_hash")
        if not stored:
            return False
        try:
            self._hasher.verify(stored, password)
            return True
        except Argon2Error:
            return False

    # -- signing key -----------------------------------------------------

    def get_signing_key(self) -> bytes:
        hexkey = self._get("signing_key")
        if hexkey is None:
            hexkey = secrets.token_hex(32)
            self._set("signing_key", hexkey)
        return bytes.fromhex(hexkey)

    # -- protection policy ----------------------------------------------

    def get_protection(self) -> str:
        return self._get("protection", "unset")

    def set_protection(self, value: str) -> None:
        if value not in PROTECTION_VALUES:
            raise ValueError(f"protection must be one of {PROTECTION_VALUES}")
        self._set("protection", value)

    # -- sessions --------------------------------------------------------
    # An allowlist: a token is only accepted while its row is here, so
    # deleting the row revokes that one session and nothing else.

    def add_session(self, sid: str, exp: int) -> None:
        with self._lock, self._conn() as c:
            c.execute("INSERT OR REPLACE INTO sessions (sid, exp, created) "
                      "VALUES (?, ?, ?)", (sid, int(exp), int(time.time())))

    def session_is_active(self, sid: str) -> bool:
        if not sid:
            return False
        with self._conn() as c:
            row = c.execute("SELECT 1 FROM sessions WHERE sid=?", (sid,)).fetchone()
        return row is not None

    def remove_session(self, sid: str) -> None:
        with self._lock, self._conn() as c:
            c.execute("DELETE FROM sessions WHERE sid=?", (sid,))

    def remove_all_sessions(self) -> None:
        with self._lock, self._conn() as c:
            c.execute("DELETE FROM sessions")

    def prune_sessions(self, now: int) -> int:
        """Drop rows whose expiry has passed. Returns the number removed."""
        with self._lock, self._conn() as c:
            return c.execute("DELETE FROM sessions WHERE exp <= ?", (int(now),)).rowcount
