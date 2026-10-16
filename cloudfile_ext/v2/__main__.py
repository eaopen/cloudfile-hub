"""Explicit fresh install/check entry point; secrets are never CLI arguments."""
import argparse
import os
from pathlib import Path
import sys

from .schema import FreshSchema


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=('install', 'check'))
    parser.add_argument('--ddl', type=Path, required=True)
    args = parser.parse_args()
    import pymysql
    try:
        with pymysql.connect(host=os.environ['CF_V2_DB_HOST'],
                             port=int(os.environ.get('CF_V2_DB_PORT', '3306')),
                             user=os.environ['CF_V2_DB_USER'],
                             password=os.environ['CF_V2_DB_PASSWORD'],
                             database=os.environ['CF_V2_DB_NAME'],
                             charset='utf8mb4', autocommit=True) as connection:
            schema = FreshSchema(connection, args.ddl.read_text())
            schema.install() if args.command == 'install' else schema.verify()
    except Exception as error:
        print('V2 schema unavailable: ' + type(error).__name__, file=sys.stderr)
        return 1
    print('V2 schema ready: 3 reviewed extension tables')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
