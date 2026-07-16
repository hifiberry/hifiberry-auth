"""Aggregate per-package classification manifests and resolve an endpoint's tier.

Each package drops /etc/hifiberry/auth.d/<service>.json:

    {
      "service": "config",
      "match_prefix": "/api/config/v1",
      "default_tier": "risky",
      "rules": [ {"tier": "ok", "methods": ["GET"], "paths": ["/version", ...]}, ... ]
    }

Resolution: the request URI is routed to the manifest whose ``match_prefix`` is
the longest prefix of the path; the remainder is matched against that manifest's
ordered rules (first hit wins), else the manifest's ``default_tier``. A URI under
no manifest, or an unreadable manifest, resolves to ``risky`` — fail safe.
"""

import fnmatch
import glob
import json
import logging
import os

logger = logging.getLogger(__name__)

TIER_RISKY = "risky"
TIER_OK = "ok"


def _segments(path: str):
    path = path.split("?", 1)[0].split("#", 1)[0]
    return [s for s in path.strip("/").split("/") if s != ""]


def _path_matches(pattern: str, path: str) -> bool:
    pat = _segments(pattern)
    seg = _segments(path)
    for i, p in enumerate(pat):
        if p == "**":          # matches the rest, including nothing (must be last)
            return True
        if i >= len(seg) or not fnmatch.fnmatchcase(seg[i], p):
            return False
    return len(pat) == len(seg)


class TierMap:
    def __init__(self, auth_d_dir: str):
        self.auth_d_dir = auth_d_dir
        self._manifests = []  # list of dicts, sorted by match_prefix length desc

    def load(self):
        manifests = []
        for path in sorted(glob.glob(os.path.join(self.auth_d_dir, "*.json"))):
            try:
                with open(path) as f:
                    m = json.load(f)
                if not isinstance(m, dict) or "match_prefix" not in m:
                    raise ValueError("missing match_prefix")
                m.setdefault("default_tier", TIER_RISKY)
                m.setdefault("rules", [])
                manifests.append(m)
            except Exception as e:
                logger.warning(f"Skipping invalid auth manifest {path}: {e}")
        # longest match_prefix first so the most specific manifest wins
        manifests.sort(key=lambda m: len(m["match_prefix"].rstrip("/")), reverse=True)
        self._manifests = manifests
        return self

    def _manifest_for(self, path: str):
        for m in self._manifests:
            prefix = m["match_prefix"].rstrip("/")
            if path == prefix or path.startswith(prefix + "/"):
                return m, path[len(prefix):] or "/"
        return None, None

    def tier(self, method: str, uri: str) -> str:
        path = uri.split("?", 1)[0]
        manifest, remainder = self._manifest_for(path)
        if manifest is None:
            return TIER_RISKY  # no manifest owns this path
        method = (method or "").upper()
        for rule in manifest.get("rules", []):
            methods = [x.upper() for x in rule.get("methods", ["*"])]
            if "*" not in methods and method not in methods:
                continue
            for pat in rule.get("paths", []):
                if _path_matches(pat, remainder):
                    return TIER_OK if rule.get("tier") == TIER_OK else TIER_RISKY
        return TIER_OK if manifest.get("default_tier") == TIER_OK else TIER_RISKY
