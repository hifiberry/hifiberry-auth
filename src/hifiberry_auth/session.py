"""Stateless signed session cookies.

A session is a compact JSON payload (version, issued-at, expiry, csrf token)
signed with HMAC-SHA256 over a per-device server key. No server-side store:
verification is signature + expiry only, and rotating the key revokes everything.
"""

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Optional


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


DEFAULT_TTL = 12 * 3600
DEFAULT_REMEMBER_TTL = 30 * 24 * 3600


class Session:
    def __init__(self, signing_key: bytes, ttl_seconds: int = DEFAULT_TTL,
                 remember_ttl_seconds: int = DEFAULT_REMEMBER_TTL,
                 clock=time.time):
        if not signing_key:
            raise ValueError("signing_key is required")
        self._key = signing_key if isinstance(signing_key, bytes) else signing_key.encode()
        self.ttl = ttl_seconds
        self.remember_ttl = remember_ttl_seconds
        self._clock = clock

    def _mac(self, body: str) -> str:
        return _b64e(hmac.new(self._key, body.encode(), hashlib.sha256).digest())

    def mint(self, remember: bool = False):
        """Return (cookie_value, csrf_token)."""
        now = int(self._clock())
        ttl = self.remember_ttl if remember else self.ttl
        csrf = secrets.token_urlsafe(32)
        payload = {"v": 1, "iat": now, "exp": now + ttl, "csrf": csrf}
        body = _b64e(json.dumps(payload, separators=(",", ":")).encode())
        return f"{body}.{self._mac(body)}", csrf

    def verify(self, cookie_value: Optional[str]) -> Optional[dict]:
        """Return the payload dict if the cookie is authentic and unexpired, else None."""
        if not cookie_value or not isinstance(cookie_value, str) or cookie_value.count(".") != 1:
            return None
        body, sig = cookie_value.split(".", 1)
        try:
            if not hmac.compare_digest(self._mac(body), sig):
                return None
            payload = json.loads(_b64d(body))
            if not isinstance(payload, dict) or "exp" not in payload or "csrf" not in payload:
                return None
            if int(self._clock()) >= int(payload["exp"]):
                return None
            return {"csrf": payload["csrf"], "exp": int(payload["exp"])}
        except Exception:
            return None
