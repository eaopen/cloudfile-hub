"""Storage classification and real disposable MariaDB transaction regressions."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
import io
import json
import os
import re
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Barrier
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from cloudfile_ext.v2.storage_reconcile import StorageConfig, StorageReconciler, valid_key


class ConfigTests(unittest.TestCase):
    def test_key_matches_c_storage_contract(self):
        for key in ('a', 'a-1', 'a' * 80):
            self.assertTrue(valid_key(key))
        for key in ('', '-a', 'a-', '../a', 'A', 'a_b', 'a' * 81):
            self.assertFalse(valid_key(key))

    def test_reads_native_and_legacy_config_and_rejects_invalid_root(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            tmp = str(root)
            conf = root / 'seafile.conf'
            conf.write_text('[cloudfile_v2]\nauto_local_root=' + tmp + '\n[storage]\nbackend=filesystem\n')
            self.assertEqual(StorageConfig.read(conf, root).root, root)
            classes = [{'storage_id': 'auto-local', **{kind: {'backend': 'fs', 'dir': tmp}
                       for kind in ('commits', 'fs', 'blocks')}}]
            (root / 'classes.json').write_text(json.dumps(classes))
            conf.write_text('[storage]\nenable_storage_classes=true\nstorage_classes_file=classes.json\n')
            self.assertEqual(StorageConfig.read(conf, root).root, root)
            conf.write_text('[cloudfile_v2]\nauto_local_root=' + tmp + '/missing\n')
            with self.assertRaisesRegex(ValueError, 'INVALID_STORAGE_ROOT'):
                StorageConfig.read(conf, root)
            (root / 'link').symlink_to(root, target_is_directory=True)
            conf.write_text('[cloudfile_v2]\nauto_local_root=' + tmp + '/link\n')
            with self.assertRaisesRegex(ValueError, 'INVALID_STORAGE_ROOT'):
                StorageConfig.read(conf, root)

    def test_managed_root_rejects_symlink_ancestor(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / 'real' / 'libraries').mkdir(parents=True)
            (root / 'alias').symlink_to(root / 'real', target_is_directory=True)
            conf = root / 'seafile.conf'
            conf.write_text('[cloudfile_v2]\nauto_local_root=' + str(root / 'alias' / 'libraries') + '\n')
            with self.assertRaisesRegex(ValueError, 'INVALID_STORAGE_ROOT'):
                StorageConfig.read(conf, root)
            config = StorageConfig(root / 'alias' / 'libraries', root)
            self.assertEqual(config.auto_error('key', str(uuid4())), 'INVALID_STORAGE_ROOT')

    def test_legacy_commands_cannot_silently_ignore_dry_run(self):
        from cloudfile_ext.v2.__main__ import main
        with patch('sys.stderr', io.StringIO()), self.assertRaises(SystemExit) as error:
            main(['reconcile', '--ddl', '/unused.sql', '--dry-run'])
        self.assertEqual(error.exception.code, 2)

    def test_legacy_entry_points_detect_existing_seafile_configuration(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            data = root / 'seafile-data'
            data.mkdir()
            conf = root / 'conf'
            conf.mkdir()
            (conf / 'seafile.conf').write_text('[cloudfile_v2]\nauto_local_root=' + str(root) + '\n')
            with patch.dict(os.environ, {'SEAFILE_DATA_DIR': str(data)}, clear=True):
                self.assertEqual(StorageConfig.detect().root, root)

    def test_cli_default_dry_run_and_machine_readable_blocked(self):
        from cloudfile_ext.v2.__main__ import main
        output = io.StringIO()
        with TemporaryDirectory() as tmp:
            conf = Path(tmp) / 'seafile.conf'
            conf.write_text('[cloudfile_v2]\nauto_local_root=' + tmp + '/missing\n')
            with redirect_stdout(output):
                code = main(['storage-reconcile', '--seafile-conf', str(conf), '--seafile-data', tmp])
        report = json.loads(output.getvalue())
        self.assertEqual((code, report['mode'], report['summary']), (2, 'dry-run', {'BLOCKED': 1}))
        self.assertEqual(report['items'][0]['reason'], 'INVALID_STORAGE_ROOT')


@unittest.skipUnless(os.environ.get('CF_STORAGE_TEST_MYSQL_PORT'), 'disposable MariaDB required')
class StorageSQLTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import pymysql
        cls.options = dict(host='127.0.0.1', port=int(os.environ['CF_STORAGE_TEST_MYSQL_PORT']),
                           user='root', password='storage-test-only', autocommit=True, charset='utf8mb4')
        cls.admin = pymysql.connect(**cls.options)
        schema_path = Path(os.environ.get('CF_V2_DDL') or (
            Path(__file__).resolve().parents[4] /
            'cloudfile-server/scripts/sql/mysql/cloudfile-v2.sql'))
        if not schema_path.is_file():
            raise unittest.SkipTest('current Server V2 DDL fixture unavailable')
        content = schema_path.read_text()
        match = re.search(r'CREATE TABLE cf_library_storage \([\s\S]*?\) ENGINE=InnoDB[^;]*;', content)
        if not match:
            raise AssertionError('Server V2 storage table definition missing')
        cls.storage_ddl = match.group().rstrip(';')

    @classmethod
    def tearDownClass(cls):
        cls.admin.close()

    def setUp(self):
        import pymysql
        self.schema = 'storage_' + uuid4().hex
        with self.admin.cursor() as cursor:
            cursor.execute('CREATE DATABASE ' + self.schema)
        self.db_options = dict(self.options, database=self.schema)
        self.connection = pymysql.connect(**self.db_options)
        self.temp = TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.native = self.root / 'seafile-data'
        self.native.mkdir()
        self.auto = self.root / 'libraries'
        self.auto.mkdir()
        self.config = StorageConfig(self.auto, self.native)
        with self.connection.cursor() as cursor:
            for table in ('Repo', 'RepoTrash', 'GarbageRepos', 'VirtualRepo'):
                cursor.execute('CREATE TABLE ' + table + '(repo_id CHAR(36) PRIMARY KEY) ENGINE=InnoDB')
            cursor.execute('CREATE TABLE RepoStorageId(repo_id CHAR(36) PRIMARY KEY,storage_id VARCHAR(255)) ENGINE=InnoDB')
            cursor.execute(self.storage_ddl)
        self.service = StorageReconciler(self.connection, self.config)
        self.service.ensure_schema()

    def tearDown(self):
        self.connection.close()
        with self.admin.cursor() as cursor:
            cursor.execute('DROP DATABASE ' + self.schema)
        self.temp.cleanup()

    def sql(self, sql, args=()):
        with self.connection.cursor() as cursor:
            cursor.execute(sql, args)
            return cursor.fetchall()

    def repo(self, *, route=None, source='Repo', key=None, state='active', physical=True):
        rid = str(uuid4())
        self.sql('INSERT INTO ' + source + '(repo_id) VALUES(%s)', (rid,))
        if route is not None:
            self.sql('INSERT INTO RepoStorageId VALUES(%s,%s)', (rid, route))
        if key is not None:
            self.sql('INSERT INTO cf_library_storage VALUES(%s,%s,%s)', (key, rid, state))
        if route and route.startswith('auto-local:') and physical and valid_key(route[11:]):
            (self.auto / route[11:] / 'storage' / 'commits' / rid).mkdir(parents=True, exist_ok=True)
        return rid

    def test_uuid_local_never_creates_extra_registry_record(self):
        rid = str(uuid4())
        self.sql('INSERT INTO Repo(repo_id) VALUES(%s)', (rid,))
        self.sql('INSERT INTO RepoStorageId(repo_id,storage_id) VALUES(%s,%s)',
                 (rid, 'auto-local:' + rid))
        (self.auto / rid / 'storage' / 'commits' / rid).mkdir(parents=True)
        inspected = self.service.inspect(rid)
        self.assertEqual(inspected['status'], 'UUID_LOCAL')
        self.assertEqual(self.service.apply_one(rid)['status'], 'UUID_LOCAL')
        report = self.service.run(apply=True, repo_id=rid)
        self.assertEqual(report['summary']['UUID_LOCAL'], 1)
        self.assertEqual(self.sql('SELECT * FROM cf_library_storage'), ())
        self.assertEqual(self.sql('SELECT storage_id FROM RepoStorageId WHERE repo_id=%s', (rid,)),
                         (('auto-local:' + rid,),))
        report = self.service.run(apply=True, batch_size=1)
        self.assertEqual(report['summary']['UUID_LOCAL'], 1)

    def test_schema_exact_idempotent_without_dynamic_ddl(self):
        self.service.ensure_schema()
        self.service.ensure_schema()
        self.sql('ALTER TABLE cf_library_storage ADD bad INT')
        with self.assertRaisesRegex(RuntimeError, 'STORAGE_SCHEMA_DRIFT'):
            self.service.ensure_schema()

    def test_native_auto_trash_and_garbage_lifecycle_and_idempotency(self):
        native = self.repo()
        auto = self.repo(route='auto-local:old-key')
        trash = self.repo(source='RepoTrash', route='auto-local:trash-key')
        garbage = self.repo(source='GarbageRepos')
        self.sql('INSERT INTO GarbageRepos VALUES(%s)', (native,))
        report = self.service.run(batch_size=1)
        self.assertEqual(report['summary'], {'AUTO_LOCAL': 2, 'NATIVE': 2, 'ORPHAN_DIRECTORY': 0})
        self.assertEqual(self.sql('SELECT * FROM cf_library_storage'), ())
        applied = self.service.run(apply=True, batch_size=1)
        self.assertEqual(applied['summary']['REGISTERED'], 4)
        expected = {native: ('native-' + native, 'active'), auto: ('old-key', 'active'),
                    trash: ('trash-key', 'active'), garbage: ('native-' + garbage, 'retired')}
        self.assertEqual({rid: (key, state) for key, rid, state in self.sql('SELECT * FROM cf_library_storage')}, expected)
        self.assertFalse(any('action' in item for item in self.service.run(apply=True)['items']))
        # The current V2 fixture intentionally contains no retired registry.

    def test_registered_pages_match_scalar_checks_without_per_repo_queries(self):
        ids = [self.repo(key=None) for _ in range(110)]
        for rid in ids:
            self.sql('INSERT INTO cf_library_storage VALUES(%s,%s,%s)',
                     ('native-' + rid, rid, 'active'))
        ids += [self.repo(route='auto-local:batch-auto', key='batch-auto'),
                self.repo(route='auto-local:batch-trash', source='RepoTrash', key='batch-trash'),
                self.repo(source='GarbageRepos')]
        self.service.apply_one(ids[-1])
        expected = {rid: self.service.inspect(rid) for rid in ids}
        with patch.object(self.service, 'inspect', wraps=self.service.inspect) as scalar, \
                patch.object(self.service, 'apply_one', wraps=self.service.apply_one) as mutate:
            report = self.service.run(apply=True, batch_size=50)
        self.assertEqual({item['repo_id']: item for item in report['items']}, expected)
        self.assertEqual(scalar.call_count, 0)
        self.assertEqual(mutate.call_count, 0)

    def test_registered_page_detects_route_collision_outside_inventory(self):
        rid = self.repo(route='auto-local:batch-collision', key='batch-collision')
        # Native collation aliases also conflict, even outside Repo/Trash/GC.
        self.sql('INSERT INTO RepoStorageId VALUES(%s,%s)',
                 (str(uuid4()), 'AUTO-LOCAL:BATCH-COLLISION'))
        item = self.service.run(apply=True, batch_size=1)['items'][0]
        self.assertEqual((item['repo_id'], item['reason']), (rid, 'KEY_OCCUPIED'))
        self.assertEqual(self.sql('SELECT COUNT(*) FROM cf_library_storage'), ((1,),))

    def test_registered_pages_recheck_routes_and_filesystem_on_every_run(self):
        rid = self.repo(route='auto-local:batch-live', key='batch-live')
        self.assertEqual(self.service.run(apply=True)['summary']['REGISTERED'], 1)
        objects = self.auto / 'batch-live' / 'storage' / 'commits' / rid
        objects.rmdir()
        objects.symlink_to(self.native, target_is_directory=True)
        self.assertEqual(self.service.run(apply=True)['items'][0]['reason'], 'SYMLINK_DIRECTORY')
        objects.unlink()
        objects.mkdir()
        self.sql("UPDATE cf_library_storage SET state='retired' WHERE repo_id=%s", (rid,))
        self.assertEqual(self.service.run(apply=True)['items'][0]['status'], 'STATE_DRIFT')
        self.sql("UPDATE RepoStorageId SET storage_id='auto-local:changed' WHERE repo_id=%s", (rid,))
        self.assertEqual(self.service.run(apply=True)['items'][0]['status'], 'BLOCKED')

    def test_virtual_skipped_in_all_native_lifecycle_locations(self):
        for source in ('Repo', 'RepoTrash', 'GarbageRepos'):
            rid = self.repo(source=source)
            self.sql('INSERT INTO VirtualRepo VALUES(%s)', (rid,))
        report = self.service.run(apply=True, batch_size=1)
        self.assertEqual(report['summary']['VIRTUAL_REPO'], 3)
        self.assertEqual(self.sql('SELECT * FROM cf_library_storage'), ())

    def test_invalid_key_missing_directory_symlink_and_empty_objects_are_blocked(self):
        cases = [('auto-local:../escape', 'INVALID_KEY', False),
                 ('auto-local:missing', 'MISSING_STORAGE_DIRECTORY', False),
                 ('auto-local:empty', 'MISSING_REPOSITORY_DIRECTORY', False)]
        (self.auto / 'empty' / 'storage').mkdir(parents=True)
        for route, reason, physical in cases:
            rid = self.repo(route=route, physical=physical)
            self.assertEqual(self.service.inspect(rid)['reason'], reason)
        rid = self.repo(route='auto-local:linked', physical=False)
        (self.auto / 'linked').symlink_to(self.native, target_is_directory=True)
        self.assertEqual(self.service.inspect(rid)['reason'], 'SYMLINK_DIRECTORY')
        rid = self.repo(route='auto-local:object-link')
        objects = self.auto / 'object-link' / 'storage' / 'commits' / rid
        objects.rmdir()
        objects.symlink_to(self.native, target_is_directory=True)
        self.assertEqual(self.service.inspect(rid)['reason'], 'SYMLINK_DIRECTORY')
        self.assertEqual(self.service.run(apply=True)['summary']['BLOCKED'], 5)

    def test_existing_binding_consistency_state_and_occupied_key(self):
        rid = self.repo()
        self.sql('INSERT INTO cf_library_storage VALUES(%s,%s,%s)', ('native-' + rid, rid, 'active'))
        self.assertEqual(self.service.inspect(rid)['status'], 'REGISTERED')
        conflict = self.repo(key='wrong')
        self.assertEqual(self.service.inspect(conflict)['reason'], 'STORAGE_BINDING_CONFLICT')
        wrong_state = self.repo(route='auto-local:wrong-state', key='wrong-state', state='retired')
        self.assertEqual(self.service.inspect(wrong_state)['status'], 'STATE_DRIFT')
        occupied = self.repo(route='auto-local:occupied')
        self.repo(key='occupied')
        self.assertEqual(self.service.inspect(occupied)['reason'], 'KEY_OCCUPIED')
        self.service.run(apply=True)
        self.assertEqual(self.sql('SELECT repo_key FROM cf_library_storage WHERE repo_id=%s', (conflict,)), (('wrong',),))

    def test_two_native_routes_cannot_claim_same_key(self):
        first = self.repo(route='auto-local:duplicate')
        second = self.repo(route='auto-local:duplicate')
        for rid in (first, second):
            self.assertEqual(self.service.apply_one(rid)['reason'], 'KEY_OCCUPIED')
        self.assertEqual(self.sql('SELECT * FROM cf_library_storage'), ())

    def test_pinned_native_class_requires_explicit_normalization(self):
        self.config.classes['legacy-default'] = {kind: {'backend': 'fs', 'dir': str(self.native)}
                                                 for kind in ('commits', 'fs', 'blocks')}
        rid = self.repo(route='legacy-default')
        self.assertEqual(self.service.run(apply=True)['summary']['NATIVE_CLASS_PINNED'], 1)
        self.assertEqual(self.sql('SELECT storage_id FROM RepoStorageId WHERE repo_id=%s', (rid,)), (('legacy-default',),))
        item = self.service.apply_one(rid, normalize=['legacy-default'])
        self.assertEqual((item['status'], item['normalized']), ('REGISTERED', True))
        self.assertEqual(self.sql('SELECT * FROM RepoStorageId WHERE repo_id=%s', (rid,)), ())
        self.assertEqual(self.sql('SELECT repo_key FROM cf_library_storage WHERE repo_id=%s', (rid,)), (('native-' + rid,),))

    def test_normalize_rolls_back_route_deletion_when_insert_fails(self):
        self.config.classes['legacy-default'] = {kind: {'backend': 'fs', 'dir': str(self.native)}
                                                 for kind in ('commits', 'fs', 'blocks')}
        rid = self.repo(route='legacy-default')
        self.sql("CREATE TRIGGER reject_storage BEFORE INSERT ON cf_library_storage FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='test refusal'")
        with self.assertRaises(Exception):
            self.service.apply_one(rid, normalize=['legacy-default'])
        self.assertEqual(self.sql('SELECT storage_id FROM RepoStorageId WHERE repo_id=%s', (rid,)), (('legacy-default',),))
        self.assertEqual(self.sql('SELECT * FROM cf_library_storage'), ())

    def test_s3_mixed_backend_external_local_and_unknown_class_blocked(self):
        for name, kinds in [('s3', {kind: {'backend': 's3', 'dir': str(self.native)} for kind in ('commits', 'fs', 'blocks')}),
                            ('other-local', {kind: {'backend': 'fs', 'dir': str(self.auto)} for kind in ('commits', 'fs', 'blocks')}),
                            ('mixed', {kind: {'backend': 'fs' if kind != 'blocks' else 's3', 'dir': str(self.native)} for kind in ('commits', 'fs', 'blocks')})]:
            self.config.classes[name] = kinds
            self.assertEqual(self.service.inspect(self.repo(route=name))['reason'], 'UNSUPPORTED_STORAGE_CLASS')
        self.assertEqual(self.service.inspect(self.repo(route='unknown'))['reason'], 'UNSUPPORTED_STORAGE_CLASS')

    def test_orphans_report_only_and_all_routes_count_as_references(self):
        (self.auto / 'orphan').mkdir()
        rid = self.repo(route='auto-local:referenced', source='GarbageRepos')
        orphan = self.service.run(apply=True)['orphan_directories']
        self.assertEqual(orphan, [{'path': str(self.auto / 'orphan'), 'status': 'ORPHAN_DIRECTORY'}])
        self.assertTrue((self.auto / 'orphan').exists())
        self.assertEqual(self.service.inspect(rid)['state'], 'retired')

    def test_concurrent_same_library_is_idempotent(self):
        import pymysql
        rid = self.repo(route='auto-local:race')
        barrier = Barrier(2)
        def worker():
            conn = pymysql.connect(**self.db_options)
            try:
                barrier.wait(timeout=5)
                return StorageReconciler(conn, self.config).apply_one(rid)
            finally:
                conn.close()
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: worker(), range(2)))
        self.assertEqual([item['status'] for item in results], ['REGISTERED', 'REGISTERED'])
        self.assertEqual(self.sql('SELECT COUNT(*) FROM cf_library_storage'), ((1,),))
        self.assertEqual(sum(item.get('action') == 'REGISTERED' for item in results), 1)

    def test_unique_key_collision_never_overwrites_and_normalize_rolls_back(self):
        rid = self.repo()
        original = self.service.inspect
        def inspected(*args, **kwargs):
            item = original(*args, **kwargs)
            if kwargs.get('lock'):
                # A conflicting committed row is already present by INSERT time.
                self.sql('INSERT INTO cf_library_storage VALUES(%s,%s,%s)',
                         ('native-' + rid, str(uuid4()), 'active'))
            return item
        with patch.object(self.service, 'inspect', side_effect=inspected):
            result = self.service.apply_one(rid)
        # Conflict insertion was part of this transaction and rolls back too.
        self.assertEqual((result['status'], result['reason']), ('BLOCKED', 'UNIQUE_KEY_CONFLICT'))
        self.assertEqual(self.sql('SELECT * FROM cf_library_storage'), ())

    def test_cli_dry_run_apply_and_blocked_exit_codes_on_real_schema(self):
        from cloudfile_ext.v2.__main__ import main
        rid = self.repo(route='auto-local:cli-library')
        conf = self.root / 'seafile.conf'
        conf.write_text('[cloudfile_v2]\nauto_local_root=' + str(self.auto) + '\n')
        args = ['storage-reconcile', '--seafile-conf', str(conf), '--seafile-data', str(self.native)]
        env = dict(CF_V2_DB_HOST='127.0.0.1', CF_V2_DB_PORT=str(self.options['port']),
                   CF_V2_DB_USER='root', CF_V2_DB_PASSWORD='storage-test-only', CF_V2_DB_NAME=self.schema)
        def invoke(extra):
            output = io.StringIO()
            with patch.dict(os.environ, env), redirect_stdout(output):
                code = main(args + extra)
            return code, json.loads(output.getvalue())
        code, report = invoke([])
        self.assertEqual((code, report['mode'], report['summary']['AUTO_LOCAL']), (0, 'dry-run', 1))
        self.assertEqual(self.sql('SELECT * FROM cf_library_storage'), ())
        code, report = invoke(['--apply', '--batch-size', '1'])
        self.assertEqual((code, report['mode'], report['summary']['REGISTERED']), (0, 'apply', 1))
        self.repo(route='unknown')
        code, report = invoke(['--dry-run'])
        self.assertEqual((code, report['summary']['BLOCKED']), (2, 1))

    def test_unique_key_collision_during_normalize_rolls_back_delete(self):
        self.config.classes['legacy-default'] = {kind: {'backend': 'fs', 'dir': str(self.native)}
                                                 for kind in ('commits', 'fs', 'blocks')}
        rid = self.repo(route='legacy-default')
        original = self.service.inspect
        def inspected(*args, **kwargs):
            item = original(*args, **kwargs)
            if kwargs.get('lock'):
                self.sql('INSERT INTO cf_library_storage VALUES(%s,%s,%s)',
                         ('native-' + rid, str(uuid4()), 'active'))
            return item
        with patch.object(self.service, 'inspect', side_effect=inspected):
            result = self.service.apply_one(rid, normalize=['legacy-default'])
        self.assertEqual((result['status'], result['reason']), ('BLOCKED', 'UNIQUE_KEY_CONFLICT'))
        self.assertEqual(self.sql('SELECT storage_id FROM RepoStorageId WHERE repo_id=%s', (rid,)), (('legacy-default',),))
        self.assertEqual(self.sql('SELECT * FROM cf_library_storage'), ())

    def test_hub_startup_uses_same_rules_and_never_normalizes_classes(self):
        from cloudfile_ext.v2.native_discovery import reconcile_from_hub
        native = self.repo()
        auto = self.repo(route='auto-local:startup')
        pinned = self.repo(route='legacy-default')
        classes = [{'storage_id': 'legacy-default', **{kind: {'backend': 'fs', 'dir': str(self.native)}
                    for kind in ('commits', 'fs', 'blocks')}}]
        conf = self.root / 'seafile.conf'
        conf.write_text('[cloudfile_v2]\nauto_local_root=' + str(self.auto) + '\n[storage]\nstorage_classes_file=classes.json\n')
        (self.root / 'classes.json').write_text(json.dumps(classes))
        modules = {'django.db': SimpleNamespace(connection=self.connection,
                   transaction=SimpleNamespace(atomic=self.service._atomic)),
                   'seahub.utils.db_api': SimpleNamespace(SeafileDB=lambda: SimpleNamespace(db_name=self.schema))}
        env = dict(SEAFILE_DATA_DIR=str(self.native), SEAFILE_CENTRAL_CONF_DIR=str(self.root))
        with patch.dict('sys.modules', modules), patch.dict(os.environ, env), self.assertLogs('cloudfile_ext.v2.native_discovery', level='WARNING'):
            report = reconcile_from_hub(batch_size=1)
        self.assertEqual((report['registered'], report['summary']['NATIVE_CLASS_PINNED']), (2, 1))
        self.assertEqual(self.sql('SELECT storage_id FROM RepoStorageId WHERE repo_id=%s', (pinned,)), (('legacy-default',),))
        self.assertEqual({row[0] for row in self.sql('SELECT repo_id FROM cf_library_storage')}, {native, auto})

    def test_null_native_route_is_blocked_instead_of_treated_as_absent(self):
        rid = self.repo()
        self.sql('INSERT INTO RepoStorageId VALUES(%s,NULL)', (rid,))
        self.assertEqual(self.service.apply_one(rid)['reason'], 'INVALID_STORAGE_ROUTE')
        self.assertEqual(self.sql('SELECT * FROM cf_library_storage'), ())

    def test_internal_storage_kind_and_repo_symlinks_are_blocked(self):
        for part in ('storage', 'commits', 'repo'):
            key = 'linked-' + part
            rid = self.repo(route='auto-local:' + key)
            directory = self.auto / key / 'storage'
            if part == 'commits':
                directory = directory / 'commits'
            elif part == 'repo':
                directory = directory / 'commits' / rid
            moved = self.root / ('outside-' + part)
            directory.rename(moved)
            directory.symlink_to(moved, target_is_directory=True)
            self.assertEqual(self.service.apply_one(rid)['reason'], 'SYMLINK_DIRECTORY')
        self.assertEqual(self.sql('SELECT * FROM cf_library_storage'), ())

    def test_trash_and_garbage_overlap_stays_active(self):
        rid = self.repo(source='RepoTrash', route='auto-local:trash-overlap')
        self.sql('INSERT INTO GarbageRepos VALUES(%s)', (rid,))
        self.assertEqual(self.service.apply_one(rid)['state'], 'active')
        self.assertEqual(self.sql('SELECT state FROM cf_library_storage WHERE repo_id=%s', (rid,)), (('active',),))

    def test_orphan_references_include_routes_outside_the_selected_batch(self):
        selected = self.repo()
        outside = self.repo(route='auto-local:outside')
        self.sql('DELETE FROM Repo WHERE repo_id=%s', (outside,))
        report = self.service.run(repo_id=selected, batch_size=1)
        self.assertEqual(len(report['items']), 1)
        self.assertEqual(report['orphan_directories'], [])

    def test_missing_registry_dry_run_reports_missing_and_apply_does_not_create(self):
        from cloudfile_ext.v2.__main__ import main
        rid = self.repo()
        self.sql('DROP TABLE cf_library_storage')
        conf = self.root / 'seafile.conf'
        conf.write_text('[cloudfile_v2]\nauto_local_root=' + str(self.auto) + '\n')
        env = dict(CF_V2_DB_HOST='127.0.0.1', CF_V2_DB_PORT=str(self.options['port']),
                   CF_V2_DB_USER='root', CF_V2_DB_PASSWORD='storage-test-only', CF_V2_DB_NAME=self.schema)
        output = io.StringIO()
        with patch.dict(os.environ, env), redirect_stdout(output):
            code = main(['storage-reconcile', '--seafile-conf', str(conf), '--seafile-data', str(self.native)])
        self.assertEqual(code, 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report['summary']['NATIVE'], 1)
        self.assertEqual(report['summary']['SCHEMA_MISSING'], 1)
        self.assertEqual(report['schema']['status'], 'SCHEMA_MISSING')
        self.assertEqual(self.sql("SELECT table_name FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='cf_library_storage'"), ())
        # The current V2 fixture intentionally contains no retired registry.
        with patch.dict(os.environ, env), redirect_stdout(io.StringIO()):
            self.assertEqual(main(['storage-reconcile', '--seafile-conf', str(conf), '--seafile-data', str(self.native), '--apply']), 1)
        self.assertEqual(self.sql(
            "SELECT table_name FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='cf_library_storage'"), ())

    def test_dry_run_works_with_select_only_user_and_read_only_transaction(self):
        import pymysql
        rid = self.repo()
        username = 'storage_ro_' + uuid4().hex[:16]
        with self.admin.cursor() as cursor:
            cursor.execute('CREATE USER %s IDENTIFIED BY %s', (username, 'select-only-test'))
            cursor.execute('GRANT SELECT ON ' + self.schema + '.* TO %s', (username,))
        try:
            for missing in (False, True):
                if missing:
                    self.sql('DROP TABLE cf_library_storage')
                readonly = pymysql.connect(**dict(self.db_options, user=username, password='select-only-test'))
                try:
                    with readonly.cursor() as cursor:
                        cursor.execute('START TRANSACTION READ ONLY')
                    report = StorageReconciler(readonly, self.config).run()
                    self.assertEqual(report['summary']['NATIVE'], 1)
                    self.assertEqual(report['schema']['status'], 'SCHEMA_MISSING' if missing else 'SCHEMA_READY')
                finally:
                    readonly.rollback()
                    readonly.close()
            self.assertEqual(self.sql("SELECT table_name FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='cf_library_storage'"), ())
        finally:
            with self.admin.cursor() as cursor:
                cursor.execute('DROP USER %s', (username,))

    def test_read_only_schema_verifier_rejects_changed_contract_without_altering_it(self):
        variants = [self.storage_ddl.replace("'reserved','active','retired'", "'reserved','active'"),
                    self.storage_ddl.replace('    UNIQUE KEY library_storage_repo (repo_id),\n', ''),
                    self.storage_ddl.replace('COLLATE=utf8mb4_bin', 'COLLATE=utf8mb4_general_ci'),
                    self.storage_ddl.replace('state VARCHAR(8) CHARACTER SET ascii COLLATE ascii_bin NOT NULL',
                                        "state VARCHAR(8) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'active'")]
        for ddl in variants:
            with self.subTest(ddl=ddl):
                self.sql('DROP TABLE cf_library_storage')
                self.sql(ddl)
                before = self.sql('SHOW CREATE TABLE cf_library_storage')
                with self.assertRaisesRegex(RuntimeError, 'STORAGE_SCHEMA_DRIFT'):
                    self.service.ensure_schema(apply=False)
                self.assertEqual(before, self.sql('SHOW CREATE TABLE cf_library_storage'))

    def test_reserved_active_compatibility_and_state_drift_do_not_write_or_block(self):
        reserved = self.repo(route='auto-local:reserved-library', key='reserved-library', state='reserved')
        retired = self.repo(source='RepoTrash', route='auto-local:retired-trash', key='retired-trash', state='retired')
        active_gc = self.repo(source='GarbageRepos', route='auto-local:active-garbage', key='active-garbage', state='active')
        native_retired = self.repo(source='RepoTrash')
        self.sql('INSERT INTO cf_library_storage VALUES(%s,%s,%s)', ('native-' + native_retired, native_retired, 'retired'))
        before = self.sql('SELECT * FROM cf_library_storage ORDER BY repo_id')
        report = self.service.run(apply=True)
        self.assertNotIn('BLOCKED', report['summary'])
        self.assertEqual(report['summary']['REGISTERED'], 1)
        self.assertEqual(report['summary']['STATE_DRIFT'], 3)
        by_id = {item['repo_id']: item for item in report['items']}
        self.assertEqual((by_id[reserved]['state'], by_id[reserved]['expected_state']), ('reserved', 'active'))
        self.assertEqual((by_id[retired]['state'], by_id[retired]['expected_state']), ('retired', 'active'))
        self.assertEqual((by_id[active_gc]['state'], by_id[active_gc]['expected_state']), ('active', 'retired'))
        self.assertEqual((by_id[native_retired]['state'], by_id[native_retired]['expected_state']), ('retired', 'active'))
        self.assertEqual(before, self.sql('SELECT * FROM cf_library_storage ORDER BY repo_id'))
        self.assertFalse(any('action' in item for item in report['items']))

    def test_native_default_class_resolves_ce_symlink_layout_only(self):
        alias = self.root / 'seafile-data-alias'
        alias.symlink_to(self.native, target_is_directory=True)
        self.config.native_dir = alias
        self.config.classes['legacy-default'] = {kind: {'backend': 'fs', 'dir': str(alias)}
                                                 for kind in ('commits', 'fs', 'blocks')}
        rid = self.repo(route='legacy-default')
        self.assertEqual(self.service.inspect(rid)['status'], 'NATIVE_CLASS_PINNED')
        self.assertEqual(self.service.apply_one(rid, normalize=['legacy-default'])['status'], 'REGISTERED')
        managed_alias = self.root / 'managed-alias'
        managed_alias.symlink_to(self.auto, target_is_directory=True)
        self.config.root = managed_alias
        self.assertEqual(self.config.auto_error('some-key', str(uuid4())), 'INVALID_STORAGE_ROOT')

    def test_wrong_database_fails_before_creating_registry(self):
        self.sql('DROP TABLE cf_library_storage')
        self.sql('RENAME TABLE Repo TO NotNativeRepo')
        with self.assertRaisesRegex(RuntimeError, 'NATIVE_SEAFILE_DATABASE_NOT_CONNECTED'):
            self.service.ensure_schema()
        self.assertEqual(self.sql("SELECT table_name FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='cf_library_storage'"), ())

    def test_write_statement_rechecks_absent_route_not_null_storage_value(self):
        rid = self.repo()
        original = self.service.inspect
        def changed(*args, **kwargs):
            item = original(*args, **kwargs)
            if kwargs.get('lock'):
                self.sql('INSERT INTO RepoStorageId VALUES(%s,NULL)', (rid,))
            return item
        with patch.object(self.service, 'inspect', side_effect=changed):
            item = self.service.apply_one(rid)
        self.assertEqual(item['reason'], 'NATIVE_ROUTE_CHANGED')
        self.assertEqual(self.sql('SELECT * FROM cf_library_storage'), ())
        self.assertEqual(self.sql('SELECT * FROM RepoStorageId'), ())

    def test_write_statement_rechecks_case_sensitive_route(self):
        rid = self.repo(route='auto-local:exact')
        original = self.service.inspect
        def changed(*args, **kwargs):
            item = original(*args, **kwargs)
            if kwargs.get('lock'):
                self.sql('UPDATE RepoStorageId SET storage_id=%s WHERE repo_id=%s', ('auto-local:EXACT', rid))
            return item
        with patch.object(self.service, 'inspect', side_effect=changed):
            item = self.service.apply_one(rid)
        self.assertEqual(item['reason'], 'NATIVE_ROUTE_CHANGED')
        self.assertEqual(self.sql('SELECT * FROM cf_library_storage'), ())
        self.assertEqual(self.sql('SELECT storage_id FROM RepoStorageId WHERE repo_id=%s', (rid,)), (('auto-local:exact',),))

    def test_route_change_between_scan_and_apply_is_reclassified(self):
        rid = self.repo()
        self.assertEqual(self.service.inspect(rid)['status'], 'NATIVE')
        self.sql('INSERT INTO RepoStorageId VALUES(%s,%s)', (rid, 's3'))
        self.assertEqual(self.service.apply_one(rid)['reason'], 'UNSUPPORTED_STORAGE_CLASS')
        self.assertEqual(self.sql('SELECT * FROM cf_library_storage'), ())
