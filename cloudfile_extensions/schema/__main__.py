"""Run with explicit DB credentials in environment, never auto-upgrade at startup."""

import argparse
import json
import os
import sys

from .runner import MigrationError, SchemaRunner


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("plan", "apply", "status", "check"))
    arguments = parser.parse_args()
    # Reuse the mysqlclient driver already shipped by CE; no extra runtime driver.
    import MySQLdb
    if not all(os.environ.get(key) for key in ("CLOUDFILE_DB_HOST", "CLOUDFILE_DB_USER", "CLOUDFILE_DB_NAME")):
        parser.error("set CLOUDFILE_DB_HOST, CLOUDFILE_DB_USER and CLOUDFILE_DB_NAME")
    try:
        connection = MySQLdb.connect(
            host=os.environ["CLOUDFILE_DB_HOST"],
            port=int(os.environ.get("CLOUDFILE_DB_PORT", "3306")),
            user=os.environ["CLOUDFILE_DB_USER"],
            password=os.environ.get("CLOUDFILE_DB_PASSWORD", ""),
            database=os.environ["CLOUDFILE_DB_NAME"],
            charset="utf8mb4", autocommit=True, connect_timeout=5,
        )
        try:
            result = getattr(SchemaRunner(connection), "require_current" if arguments.command == "check" else arguments.command)()
            print(json.dumps(result if result is not None else {"current": True}))
        finally:
            connection.close()
    except (MigrationError, MySQLdb.MySQLError, ValueError):
        print("CloudFile schema command failed; check configuration and migration ledger", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
