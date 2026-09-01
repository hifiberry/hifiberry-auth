# hifiberry-auth

The authentication/authorization gateway for HiFiBerryOS.

A small service on `127.0.0.1:1089` that answers nginx's
[`auth_request`](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html)
for every `/api/…` call. It classifies each request into one of two tiers and
decides whether it needs a password:

- **`ok`** — everyday music use: playback, volume, library browsing, player
  lifecycle, audio/DSP. Never needs a password.
- **`risky`** — anything that changes the system, touches credentials or
  affects privacy: network and hostname, software installation, factory reset,
  starting a microphone recording. Needs the device password.

Authorization is enforced at the gateway, not in each backend. The backends
bind to localhost and rely on nginx being the only reachable door.

## Classification manifests

Which endpoint is `ok` and which is `risky` is data, not code. Each package
ships a drop-in describing its own API into `/etc/hifiberry/auth.d/`:

```json
{
  "service": "config",
  "match_prefix": "/api/config/v1",
  "default_tier": "risky",
  "rules": [
    { "tier": "ok", "methods": ["GET"], "paths": ["/version", "/systeminfo"] },
    { "tier": "risky", "methods": ["*"], "paths": ["/**"] }
  ]
}
```

A request is routed to the manifest with the longest matching `match_prefix`;
rules are evaluated in order, first hit wins. `*` matches one path segment,
`**` the rest. Anything no manifest covers resolves to `risky` — fail safe.

Manifests are read at startup. The package therefore ships a dpkg trigger on
`/etc/hifiberry/auth.d`, so installing a package that drops a manifest
restarts this service automatically.

## Protection policy

| Policy | `ok` | `risky` | Meaning |
|---|---|---|---|
| `unset` | allowed | prompt to set a password | first boot |
| `off` | allowed | allowed | no password at all |
| `risky` | allowed | needs sign-in | **default** |
| `all` | needs sign-in | needs sign-in | password for the whole UI |

## Sessions

The password is hashed with **argon2id** and stored in SQLite at
`/var/lib/hifiberry-auth/auth.db`. The session is a stateless
**HMAC-SHA256-signed cookie** (`hifiberry_session`, `HttpOnly`, `SameSite=Lax`)
carrying its own issue/expiry timestamps and a CSRF token — there is no
server-side session table. Rotating the signing key (or deleting the database)
revokes every session. Sessions last 12 hours, or 30 days when the user opts
into staying signed in.

Risky **non-GET** requests must additionally carry the session's CSRF token in
`X-CSRF-Token`.

No `Secure` flag is set on the cookie: HiFiBerryOS is served over plain HTTP on
the local network. The model protects against unauthenticated API use, not
against an attacker who can read or modify LAN traffic.

## API

`/api/auth/…` is always reachable (nginx sets `auth_request off` for it):

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/auth/status` | GET | `{protection, has_password, authenticated}` |
| `/api/auth/set-password` | POST | set/change the password, mints a session |
| `/api/auth/login` | POST | sign in (rate limited), mints a session |
| `/api/auth/logout` | POST | clear the session cookie |
| `/api/auth/policy` | POST | set the protection policy |
| `/api/auth/csrf` | GET | current session's CSRF token |

`GET /_auth/verify` is the internal nginx subrequest target and is not
reachable from the browser.

## Build

```
./build.sh          # from packages/hifiberry-auth in the hifiberry-os tree
```

## Test

```
python3 -m pytest tests/
```

## Files

| Path | Purpose |
|---|---|
| `/var/lib/hifiberry-auth/auth.db` | password hash, signing key, policy |
| `/etc/hifiberry/auth.d/*.json` | per-service classification manifests |
| `/etc/nginx/hifiberry-auth.d/00-verify.conf` | server-level `auth_request` wiring |

## License

MIT
