"""Explicit install/check and storage preflight; secrets are never CLI arguments."""
import argparse
import json
import os
from pathlib import Path
import sys

from .schema import FreshSchema
from .native_discovery import NativeLibraryDiscovery
from .storage_reconcile import StorageConfig, StorageReconciler


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=('install', 'check', 'discover', 'reconcile', 'inspect',
                                            'storage-reconcile'))
    parser.add_argument('--repo-id', help='original native Seafile repository UUID')
    parser.add_argument('--ddl', type=Path)
    parser.add_argument('--seafile-conf', type=Path)
    parser.add_argument('--seafile-data', type=Path)
    parser.add_argument('--batch-size', type=int, default=500)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--dry-run', action='store_true')
    modes.add_argument('--apply', action='store_true')
    parser.add_argument('--normalize-native-class', action='append', default=[], metavar='ID')
    args = parser.parse_args(argv)
    storage = args.command == 'storage-reconcile'
    if storage and (not args.seafile_conf or not args.seafile_data):
        parser.error('storage-reconcile requires --seafile-conf and --seafile-data')
    if not storage and (args.dry_run or args.apply or args.normalize_native_class):
        parser.error('storage mode flags require storage-reconcile')
    if not storage and not args.ddl:
        parser.error('--ddl is required for schema commands')
    if not 1 <= args.batch_size <= 2000:
        parser.error('--batch-size must be between 1 and 2000')
    import pymysql
    try:
        config = StorageConfig.detect(args.seafile_conf, args.seafile_data)
        with pymysql.connect(host=os.environ['CF_V2_DB_HOST'],
                             port=int(os.environ.get('CF_V2_DB_PORT', '3306')),
                             user=os.environ['CF_V2_DB_USER'],
                             password=os.environ['CF_V2_DB_PASSWORD'],
                             database=os.environ['CF_V2_DB_NAME'],
                             charset='utf8mb4', autocommit=True) as connection:
            if storage:
                discovery = StorageReconciler(connection, config)
                report = discovery.run(apply=args.apply, batch_size=args.batch_size,
                                       normalize=args.normalize_native_class, repo_id=args.repo_id)
                print(json.dumps(report, sort_keys=True))
                return 2 if report['summary'].get('BLOCKED', 0) else 0
            NativeLibraryDiscovery.check_native_schema(connection)
            schema = FreshSchema(
                connection, args.ddl.read_text(),
                edit_ddl=args.ddl.with_name('cloudfile-v2-edit.sql').read_text(),
                audit_ddl=args.ddl.with_name('cloudfile-v2-audit.sql').read_text())
            if args.command == 'install':
                schema.install()
            else:
                schema.verify()
            discovery = NativeLibraryDiscovery(connection, config)
            if args.command in ('install', 'reconcile'):
                print(json.dumps({'statuses': discovery.reconcile(args.repo_id),
                                  'unresolved_registry': discovery.unresolved_registry_count()}, sort_keys=True))
            elif args.command == 'inspect':
                if not args.repo_id:
                    parser.error('inspect requires --repo-id')
                print(json.dumps(discovery.inspect(args.repo_id), sort_keys=True))
            elif args.command == 'discover':
                print(json.dumps(discovery.summary(args.repo_id), sort_keys=True))
    except Exception as error:
        if storage:
            reason = str(error) if isinstance(error, (ValueError, RuntimeError)) else type(error).__name__
            report = dict(mode='apply' if args.apply else 'dry-run', summary={'BLOCKED': 1},
                          items=[{'status': 'BLOCKED', 'reason': reason}], orphan_directories=[])
            print(json.dumps(report, sort_keys=True))
            return 2 if isinstance(error, ValueError) else 1
        print('V2 schema unavailable: ' + type(error).__name__, file=sys.stderr)
        return 1
    print('V2 schema ready: 5 reviewed extension tables, native discovery checked')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
