import json
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from hifiberry_auth.manifests import TierMap

CONFIG_MANIFEST = {
    "service": "config",
    "match_prefix": "/api/config/v1",
    "default_tier": "risky",
    "rules": [
        {"tier": "ok", "methods": ["GET"], "paths": ["/version", "/systeminfo"]},
        {"tier": "ok", "methods": ["GET"], "paths": ["/systemd/service/*"]},
        {"tier": "ok", "methods": ["POST"], "paths": ["/systemd/service/*/*"]},
        {"tier": "risky", "methods": ["*"], "paths": ["/**"]},
    ],
}


def _map(tmp_path, *manifests):
    d = tmp_path / "auth.d"
    d.mkdir()
    for i, m in enumerate(manifests):
        (d / f"{i}.json").write_text(json.dumps(m))
    tm = TierMap(str(d))
    tm.load()
    return tm


def test_ok_get(tmp_path):
    tm = _map(tmp_path, CONFIG_MANIFEST)
    assert tm.tier("GET", "/api/config/v1/version") == "ok"
    assert tm.tier("GET", "/api/config/v1/systeminfo") == "ok"


def test_risky_post(tmp_path):
    tm = _map(tmp_path, CONFIG_MANIFEST)
    assert tm.tier("POST", "/api/config/v1/system/reboot") == "risky"
    assert tm.tier("POST", "/api/config/v1/extensions/x/install") == "risky"


def test_player_service_control_is_ok_via_glob(tmp_path):
    tm = _map(tmp_path, CONFIG_MANIFEST)
    assert tm.tier("POST", "/api/config/v1/systemd/service/mpd/start") == "ok"
    assert tm.tier("GET", "/api/config/v1/systemd/service/mpd") == "ok"
    # one segment vs two: status (GET, 1 seg) ok, but a POST to just the service
    # isn't matched by the ok rules and falls through to risky
    assert tm.tier("POST", "/api/config/v1/systemd/service/mpd") == "risky"


def test_unlisted_path_uses_default_tier(tmp_path):
    tm = _map(tmp_path, CONFIG_MANIFEST)
    assert tm.tier("GET", "/api/config/v1/totally/unknown") == "risky"


def test_uri_under_no_prefix_is_risky(tmp_path):
    tm = _map(tmp_path, CONFIG_MANIFEST)
    assert tm.tier("GET", "/api/audiocontrol/now-playing") == "risky"


def test_longest_prefix_wins(tmp_path):
    broad = {"service": "a", "match_prefix": "/api", "default_tier": "ok", "rules": []}
    narrow = {"service": "b", "match_prefix": "/api/config/v1", "default_tier": "risky",
              "rules": [{"tier": "risky", "methods": ["*"], "paths": ["/**"]}]}
    tm = _map(tmp_path, broad, narrow)
    # /api/config/v1/... routes to the narrower (risky) manifest, not the broad ok one
    assert tm.tier("POST", "/api/config/v1/system/reboot") == "risky"
    # something only under /api goes to the broad manifest
    assert tm.tier("GET", "/api/other/thing") == "ok"


def test_malformed_manifest_is_skipped(tmp_path):
    d = tmp_path / "auth.d"
    d.mkdir()
    (d / "good.json").write_text(json.dumps(CONFIG_MANIFEST))
    (d / "bad.json").write_text("{ not json")
    tm = TierMap(str(d))
    tm.load()
    assert tm.tier("GET", "/api/config/v1/version") == "ok"  # good one still works


def test_method_wildcard_and_query_string_stripped(tmp_path):
    tm = _map(tmp_path, CONFIG_MANIFEST)
    # query strings must not defeat matching
    assert tm.tier("GET", "/api/config/v1/version?foo=bar") == "ok"


def test_no_manifests_everything_risky(tmp_path):
    d = tmp_path / "auth.d"
    d.mkdir()
    tm = TierMap(str(d))
    tm.load()
    assert tm.tier("GET", "/api/config/v1/version") == "risky"
