"""Entry point: serve hifiberry-auth on 127.0.0.1:1089 via Waitress."""
import argparse
import logging

from waitress import serve

from .store import AuthStore
from .manifests import TierMap
from .server import create_app

DEFAULT_DB = "/var/lib/hifiberry-auth/auth.db"
DEFAULT_AUTH_D = "/etc/hifiberry/auth.d"


def main():
    p = argparse.ArgumentParser(description="HiFiBerry auth/authz gateway service")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=1089)
    p.add_argument("--db", default=DEFAULT_DB)
    p.add_argument("--auth-d", default=DEFAULT_AUTH_D)
    args = p.parse_args()
    logging.basicConfig(level=logging.INFO)

    store = AuthStore(db_path=args.db)
    tier_map = TierMap(args.auth_d).load()
    app = create_app(store, tier_map)
    logging.getLogger(__name__).info(
        "hifiberry-auth on %s:%s (auth.d=%s)", args.host, args.port, args.auth_d)
    serve(app, host=args.host, port=args.port, threads=8)


if __name__ == "__main__":
    main()
