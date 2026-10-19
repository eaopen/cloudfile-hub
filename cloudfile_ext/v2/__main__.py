"""Explicit fresh install/check entry point; secrets are never CLI arguments."""
import argparse
import json
import os
from pathlib import Path
import sys

from .schema import FreshSchema
from .native_discovery import NativeLibraryDiscovery


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=('install', 'check', 'discover', 'reconcile', 'inspect'))
    parser.add_argument('--repo-id', help='original native Seafile repository UUID')
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
            NativeLibraryDiscovery.check_native_schema(connection)
            schema = FreshSchema(connection, args.ddl.read_text())
            if args.command == 'install':
                schema.install()
            else:
                schema.verify()
            discovery = NativeLibraryDiscovery(connection)
            if args.command in ('install', 'reconcile'):
                print(json.dumps({"statuses": discovery.reconcile(args.repo_id),
                                  "unresolved_registry": discovery.unresolved_registry_count()}, sort_keys=True))
            elif args.command == 'inspect':
                if not args.repo_id:
                    parser.error('inspect requires --repo-id')
                print(json.dumps(discovery.inspect(args.repo_id), sort_keys=True))
            elif args.command == 'discover':
                print(json.dumps(discovery.summary(args.repo_id), sort_keys=True))
    except Exception as error:
        print('V2 schema unavailable: ' + type(error).__name__, file=sys.stderr)
        return 1
    print('V2 schema ready: 3 reviewed extension tables, native discovery checked')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
