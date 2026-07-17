"""Persistent auth state: the device password (argon2id), the session signing
key, and the protection policy — a small SQLite key/value store."""

import os
import secrets
import sqlite3
import threading

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
