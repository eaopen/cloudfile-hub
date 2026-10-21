"""Reconcile native storage facts without moving bytes or reading legacy metadata."""
from collections import Counter
from configparser import ConfigParser
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re

from .schema import identifier

KINDS = ('commits', 'fs', 'blocks')


def valid_key(key):
    return isinstance(key, str) and bool(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,78}[a-z0-9])?', key))


def real_directory(path):
    return path.is_dir() and not path.is_symlink()


def symlink_in_path(path):
    """Reject managed-root aliases, including any ancestor component."""
    return any(component.is_symlink() for component in (path, *path.parents))


class StorageConfig:
    def __init__(self, root=None, native_dir=None, classes=()):
        self.root = Path(root) if root else None
        self.native_dir = Path(native_dir) if native_dir else None
        self.classes = {}
        for item in classes:
            if not isinstance(item, dict):
                raise ValueError('INVALID_STORAGE_CLASSES')
            sid = item.get('storage_id')
            if not isinstance(sid, str) or sid in self.classes:
                raise ValueError('INVALID_STORAGE_CLASSES')
            self.classes[sid] = item

    @classmethod
    def read(cls, conf, native_dir):
        conf = Path(conf)
        parser = ConfigParser(interpolation=None)
        with conf.open() as stream:
            parser.read_file(stream)
        classes = []
        # Read configured JSON even during an explicit transition from multi.
        filename = parser.get('storage', 'storage_classes_file', fallback='')
        inline = os.environ.get('CF_STORAGE_CLASSES_JSON', '')
        if inline:
            classes = json.loads(inline)
        elif filename:
            path = Path(filename)
            if not path.is_absolute():
                path = conf.parent / path
            classes = json.loads(path.read_text())
        if not isinstance(classes, list) or any(not isinstance(item, dict) for item in classes):
            raise ValueError('INVALID_STORAGE_CLASSES')
        root = parser.get('cloudfile_v2', 'auto_local_root', fallback='')
        if not root:
            templates = [item for item in classes if item.get('storage_id') == 'auto-local']
            if templates:
                template = templates[0]
                roots = {template.get(kind, {}).get('dir') for kind in KINDS}
                if (len(roots) != 1 or None in roots or
                        any(template.get(kind, {}).get('backend') != 'fs' for kind in KINDS)):
                    raise ValueError('INVALID_AUTO_LOCAL_TEMPLATE')
                root = roots.pop()
        config = cls(root, native_dir, classes)
        if config.root and (not config.root.is_absolute() or symlink_in_path(config.root) or not real_directory(config.root)):
            raise ValueError('INVALID_STORAGE_ROOT')
        return config

    @classmethod
    def detect(cls, conf=None, native_dir=None):
        """Use existing Seafile layout/environment for legacy entry points."""
        native_dir = native_dir or os.environ.get('SEAFILE_DATA_DIR')
        if not native_dir:
            native_dir = next((path for path in ('/shared/seafile/seafile-data', '/opt/seafile/seafile-data')
                               if Path(path).is_dir()), None)
        if not native_dir:
            return None
        if conf:
            return cls.read(conf, native_dir)
        central = os.environ.get('SEAFILE_CENTRAL_CONF_DIR')
        candidates = ([Path(central) / 'seafile.conf'] if central else []) + [
            Path(native_dir).parent / 'conf' / 'seafile.conf',
            Path(native_dir) / 'seafile.conf',
            Path('/shared/seafile/conf/seafile.conf'), Path('/opt/seafile/conf/seafile.conf')]
        return next((cls.read(path, native_dir) for path in candidates if path.is_file()), None)

    def native_class(self, route):
        item = self.classes.get(route, {})
        if not self.native_dir:
            return False
        try:
            native = self.native_dir.resolve(strict=True)
            if not native.is_dir():
                return False
            # CE's /opt/seafile/seafile-data alias is normal. Only native
            # aliases are resolved; managed automatic roots reject symlinks.
            return all(item.get(kind, {}).get('backend') == 'fs' and
                       item[kind].get('dir') and Path(item[kind]['dir']).is_absolute() and
                       Path(item[kind]['dir']).resolve(strict=True).is_dir() and
                       Path(item[kind]['dir']).resolve(strict=True) == native for kind in KINDS)
        except (OSError, RuntimeError):
            return False

    def auto_error(self, key, repo_id):
        if not valid_key(key):
            return 'INVALID_KEY'
        if not self.root or symlink_in_path(self.root) or not real_directory(self.root):
            return 'INVALID_STORAGE_ROOT'
        base = self.root / key
        storage = base / 'storage'
        if base.is_symlink() or storage.is_symlink():
            return 'SYMLINK_DIRECTORY'
        if not real_directory(base) or not real_directory(storage):
            return 'MISSING_STORAGE_DIRECTORY'
        found = False
        for kind in KINDS:
            directory = storage / kind
            objects = directory / repo_id
            if directory.is_symlink() or objects.is_symlink():
                return 'SYMLINK_DIRECTORY'
            if real_directory(directory) and real_directory(objects):
                found = True
        return None if found else 'MISSING_REPOSITORY_DIRECTORY'


class StorageReconciler:
    def __init__(self, connection, config=None, *, schema=None, atomic=None):
        self.connection = connection
        self.config = config or StorageConfig()
        self.schema = schema
        self.prefix = identifier(schema) + '.' if schema else ''
        self.atomic = atomic or self._atomic
        self.registry_present = True

    def table(self, name):
        return self.prefix + identifier(name)

    @contextmanager
    def _atomic(self):
        self.connection.begin()
        try:
            yield
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise

    def ensure_schema(self, *, apply=True):
        """Verify the current V2 storage table, never initialize DDL.

        Fresh setup owns schema creation. Existing repositories are discovered
        only from native Seafile facts, not historical CloudFile records.
        """
        with self.connection.cursor() as cursor:
            required = {'Repo', 'RepoTrash', 'GarbageRepos', 'VirtualRepo', 'RepoStorageId'}
            cursor.execute("SELECT table_name FROM information_schema.tables "
                           "WHERE table_schema=COALESCE(%s,DATABASE()) AND table_name IN "
                           "('Repo','RepoTrash','GarbageRepos','VirtualRepo','RepoStorageId')", (self.schema,))
            if {row[0] for row in cursor.fetchall()} != required:
                raise RuntimeError('NATIVE_SEAFILE_DATABASE_NOT_CONNECTED')
            cursor.execute("SELECT engine,table_collation FROM information_schema.tables "
                           "WHERE table_schema=COALESCE(%s,DATABASE()) AND table_name='cf_library_storage'",
                           (self.schema,))
            table = cursor.fetchone()
            if table is None:
                self.registry_present = False
                if not apply:
                    return 'SCHEMA_MISSING'
                raise RuntimeError('V2_FIVE_TABLE_SCHEMA_REQUIRED')
            cursor.execute("SELECT column_name,column_type,is_nullable,column_default,character_set_name,"
                           "collation_name,extra FROM information_schema.columns "
                           "WHERE table_schema=COALESCE(%s,DATABASE()) AND table_name='cf_library_storage' "
                           "ORDER BY ordinal_position", (self.schema,))
            columns = list(cursor.fetchall())
            expected_columns = [(name, kind, 'NO', None, 'ascii', 'ascii_bin', '') for name, kind in
                                (('repo_key', 'varchar(80)'), ('repo_id', 'char(36)'), ('state', 'varchar(8)'))]
            cursor.execute("SELECT index_name,non_unique,seq_in_index,column_name,sub_part,index_type "
                           "FROM information_schema.statistics WHERE table_schema=COALESCE(%s,DATABASE()) "
                           "AND table_name='cf_library_storage' ORDER BY index_name,seq_in_index", (self.schema,))
            indexes = sorted(cursor.fetchall(), key=lambda row: (row[0], row[2]))
            expected_indexes = [('PRIMARY', 0, 1, 'repo_key', None, 'BTREE'),
                                ('library_storage_repo', 0, 1, 'repo_id', None, 'BTREE')]
            # MariaDB hides CHECK_CONSTRAINTS from SELECT-only users even
            # when SHOW CREATE TABLE exposes their table's complete contract.
            cursor.execute('SHOW CREATE TABLE ' + self.table('cf_library_storage'))
            definition = cursor.fetchone()[1]
            checks = re.findall(r'CONSTRAINT\s+`?([A-Za-z0-9_]+)`?\s+CHECK\s+([^\n]+)',
                                definition, flags=re.IGNORECASE)
            def clause(value):
                # MySQL may add _ascii literal introducers and parentheses;
                # these spell the same reviewed expression on MariaDB.
                value = re.sub(r"_[a-zA-Z0-9]+(?=')", '', value)
                return re.sub(r'[\s`()]+', '', value).lower()
            valid_check = (len(checks) == 1 and checks[0][0] == 'library_storage_state' and
                           clause(checks[0][1]) == clause("state IN ('reserved','active','retired')"))
            if (table != ('InnoDB', 'utf8mb4_bin') or columns != expected_columns or
                    indexes != expected_indexes or not valid_check or 'NOT ENFORCED' in definition.upper() or
                    'FOREIGN KEY' in definition.upper()):
                raise RuntimeError('STORAGE_SCHEMA_DRIFT')
        self.registry_present = True
        return 'SCHEMA_READY'

    def sources(self):
        return ' UNION '.join('SELECT repo_id FROM ' + self.table(name)
                              for name in ('Repo', 'RepoTrash', 'GarbageRepos'))

    def scan(self, batch_size=500):
        if not 1 <= batch_size <= 2000:
            raise ValueError('batch_size out of range')
        after = ''
        while True:
            with self.connection.cursor() as cursor:
                cursor.execute('SELECT repo_id FROM (' + self.sources() + ') sources '
                               'WHERE repo_id>%s ORDER BY repo_id LIMIT %s', (after, batch_size))
                ids = [row[0] for row in cursor.fetchall()]
            if not ids:
                return
            for repo_id in ids:
                yield self.inspect(repo_id)
            after = ids[-1]

    def inspect(self, repo_id, *, lock=False):
        from .native_discovery import native_key
        tables = {name: self.table(name) for name in
                  ('Repo', 'RepoTrash', 'GarbageRepos', 'VirtualRepo', 'RepoStorageId', 'cf_library_storage')}
        if not self.registry_present:
            tables['cf_library_storage'] = '(SELECT NULL AS repo_id,NULL AS repo_key,NULL AS state WHERE 1=0)'
        sql = ('SELECT r.repo_id,t.repo_id,g.repo_id,v.repo_id,s.repo_id,s.storage_id,c.repo_key,c.state '
               'FROM (SELECT %s AS repo_id) i '
               'LEFT JOIN {Repo} r ON r.repo_id=i.repo_id '
               'LEFT JOIN {RepoTrash} t ON t.repo_id=i.repo_id '
               'LEFT JOIN {GarbageRepos} g ON g.repo_id=i.repo_id '
               'LEFT JOIN {VirtualRepo} v ON v.repo_id=i.repo_id '
               'LEFT JOIN {RepoStorageId} s ON s.repo_id=i.repo_id '
               'LEFT JOIN {cf_library_storage} c ON c.repo_id=i.repo_id').format(**tables)
        with self.connection.cursor() as cursor:
            cursor.execute(sql + (' FOR UPDATE' if lock else ''), (repo_id,))
            present, trash, garbage, virtual, route_owner, route, key, state = cursor.fetchone()
        item = dict(repo_id=repo_id, storage_id=route, status='BLOCKED')
        def blocked(reason):
            return dict(item, reason=reason)
        if virtual:
            return dict(item, status='VIRTUAL_REPO')
        if not (present or trash or garbage):
            return blocked('NATIVE_RESOURCE_MISSING')
        if route_owner is not None and route is None:
            return blocked('INVALID_STORAGE_ROUTE')
        marker = native_key(repo_id)
        if marker is None:
            return blocked('INVALID_NATIVE_REPO_ID')
        target_state = 'active' if present or trash else 'retired'
        if route is None:
            category, wanted = 'NATIVE', marker
        elif route.startswith('auto-local:'):
            category, wanted = 'AUTO_LOCAL', route[len('auto-local:'):]
            error = self.config.auto_error(wanted, repo_id)
            if error:
                return blocked(error)
        elif self.config.native_class(route):
            category, wanted = 'NATIVE_CLASS_PINNED', marker
        else:
            return blocked('UNSUPPORTED_STORAGE_CLASS')
        item.update(category=category, repo_key=wanted, state=target_state)
        with self.connection.cursor() as cursor:
            if self.registry_present:
                cursor.execute('SELECT repo_id FROM ' + self.table('cf_library_storage') +
                               ' WHERE repo_key=%s AND repo_id<>%s', (wanted, repo_id))
                if cursor.fetchone():
                    return blocked('KEY_OCCUPIED')
            if category == 'AUTO_LOCAL':
                cursor.execute('SELECT repo_id FROM ' + self.table('RepoStorageId') +
                               ' WHERE storage_id=%s AND repo_id<>%s', (route, repo_id))
                if cursor.fetchone():
                    return blocked('KEY_OCCUPIED')
        if key is not None:
            if key != wanted or category == 'NATIVE_CLASS_PINNED':
                return blocked('STORAGE_BINDING_CONFLICT')
            item.update(state=state, expected_state=target_state)
            if state != target_state and not (state == 'reserved' and target_state == 'active'):
                return dict(item, status='STATE_DRIFT', reason='LIFECYCLE_STATE_MISMATCH')
            return dict(item, status='REGISTERED')
        return dict(item, status=category)

    def apply_one(self, repo_id, normalize=()):
        try:
            with self.atomic():
                item = self.inspect(repo_id, lock=True)
                category = item['status']
                normalize_route = (category == 'NATIVE_CLASS_PINNED' and item['storage_id'] in normalize)
                if category not in ('NATIVE', 'AUTO_LOCAL') and not normalize_route:
                    return item
                if normalize_route:
                    with self.connection.cursor() as cursor:
                        cursor.execute('DELETE FROM ' + self.table('RepoStorageId') +
                                       ' WHERE repo_id=%s AND BINARY storage_id = BINARY %s',
                                       (repo_id, item['storage_id']))
                        if cursor.rowcount != 1:
                            raise RuntimeError('NATIVE_ROUTE_CHANGED')
                route = None if normalize_route else item['storage_id']
                route_check = 's.repo_id IS NULL' if route is None else 'BINARY s.storage_id = BINARY %s'
                sql = ('INSERT INTO ' + self.table('cf_library_storage') + '(repo_key,repo_id,state) '
                       'SELECT %s,i.repo_id,CASE WHEN r.repo_id IS NOT NULL OR t.repo_id IS NOT NULL '
                       "THEN 'active' ELSE 'retired' END FROM (SELECT %s AS repo_id) i "
                       'LEFT JOIN ' + self.table('Repo') + ' r ON r.repo_id=i.repo_id '
                       'LEFT JOIN ' + self.table('RepoTrash') + ' t ON t.repo_id=i.repo_id '
                       'LEFT JOIN ' + self.table('GarbageRepos') + ' g ON g.repo_id=i.repo_id '
                       'LEFT JOIN ' + self.table('VirtualRepo') + ' v ON v.repo_id=i.repo_id '
                       'LEFT JOIN ' + self.table('RepoStorageId') + ' s ON s.repo_id=i.repo_id '
                       'WHERE (r.repo_id IS NOT NULL OR t.repo_id IS NOT NULL OR g.repo_id IS NOT NULL) '
                       'AND v.repo_id IS NULL AND ' + route_check + ' FOR UPDATE')
                with self.connection.cursor() as cursor:
                    cursor.execute(sql, (item['repo_key'], repo_id) + (() if route is None else (route,)))
                    if cursor.rowcount != 1:
                        raise RuntimeError('NATIVE_ROUTE_CHANGED')
                after = self.inspect(repo_id)
                if after['status'] != 'REGISTERED':
                    raise RuntimeError('STORAGE_FACTS_CHANGED')
                return dict(after, action='REGISTERED', normalized=normalize_route)
        except Exception as error:
            if getattr(error, 'args', (None,))[0] == 1062:
                # A competing writer wins only if its complete binding agrees.
                after = self.inspect(repo_id)
                if after['status'] == 'REGISTERED':
                    return after
                return dict(after, status='BLOCKED', reason='UNIQUE_KEY_CONFLICT')
            if isinstance(error, RuntimeError) and str(error) in ('NATIVE_ROUTE_CHANGED', 'STORAGE_FACTS_CHANGED'):
                return dict(repo_id=repo_id, status='BLOCKED', reason=str(error))
            raise

    def orphans(self):
        if not self.config.root or not real_directory(self.config.root):
            return []
        with self.connection.cursor() as cursor:
            cursor.execute('SELECT storage_id FROM ' + self.table('RepoStorageId') +
                           " WHERE storage_id LIKE 'auto-local:%'")
            referenced = {row[0][len('auto-local:'):] for row in cursor.fetchall()}
        return [dict(path=str(path), status='ORPHAN_DIRECTORY')
                for path in sorted(self.config.root.iterdir())
                if (path.is_dir() or path.is_symlink()) and path.name not in referenced]

    def run(self, *, apply=False, batch_size=500, normalize=(), repo_id=None):
        schema_status = self.ensure_schema(apply=apply)
        items = []
        iterator = (self.inspect(repo_id),) if repo_id else self.scan(batch_size)
        for item in iterator:
            if apply:
                item = self.apply_one(item['repo_id'], normalize)
            items.append(item)
        orphans = self.orphans()
        counts = Counter(item['status'] for item in items)
        counts['ORPHAN_DIRECTORY'] += len(orphans)
        if schema_status == 'SCHEMA_MISSING':
            counts['SCHEMA_MISSING'] = 1
        return dict(schema={'status': schema_status}, mode='apply' if apply else 'dry-run', summary=dict(sorted(counts.items())),
                    items=items, orphan_directories=orphans)
