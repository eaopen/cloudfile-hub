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
        return 'SCHEMA_READY'

    def sources(self):
        return ' UNION '.join('SELECT repo_id FROM ' + self.table(name)
                              for name in ('Repo','RepoTrash','GarbageRepos','RepoStorageId'))

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
            yield from self.inspect_batch(ids)
            after = ids[-1]

    def inspect_batch(self, repo_ids):
        """Read already-registered bindings in bounded pages, without stale caches.

        A full inventory used to repeat every join and route-conflict scan twice
        per repository, exceeding callers' HTTP deadlines. Only verified existing
        bindings take this read-only path; missing or abnormal bindings still use
        inspect/apply_one and its locked mutation checks.
        """
        sources = ' UNION ALL '.join('SELECT %s AS repo_id' for _ in repo_ids)
        tables = {name: self.table(name) for name in ('Repo','RepoTrash','GarbageRepos','VirtualRepo','RepoStorageId')}
        sql = ('SELECT i.repo_id,r.repo_id,t.repo_id,g.repo_id,v.repo_id,s.repo_id,s.storage_id,'
               'EXISTS(SELECT 1 FROM {RepoStorageId} d WHERE d.storage_id=s.storage_id AND d.repo_id<>i.repo_id) '
               'FROM (' + sources + ') i LEFT JOIN {Repo} r ON r.repo_id=i.repo_id '
               'LEFT JOIN {RepoTrash} t ON t.repo_id=i.repo_id LEFT JOIN {GarbageRepos} g ON g.repo_id=i.repo_id '
               'LEFT JOIN {VirtualRepo} v ON v.repo_id=i.repo_id LEFT JOIN {RepoStorageId} s ON s.repo_id=i.repo_id').format(**tables)
        with self.connection.cursor() as cursor:
            cursor.execute(sql,tuple(repo_ids))
            rows = cursor.fetchall()
        for rid, live, trash, garbage, virtual, owner, route, duplicate in rows:
            item = dict(repo_id=rid, storage_id=route)
            if virtual:
                yield dict(item,status='VIRTUAL_REPO')
            elif not (live or trash or garbage):
                yield dict(item,status='BLOCKED',reason='NATIVE_RESOURCE_MISSING')
            elif (owner is None and not self.config.root) or route == 'cf-native':
                yield dict(item,status='REGISTERED',category='NATIVE')
            elif route and route.startswith('auto-local:'):
                key = route[11:]
                error = 'KEY_OCCUPIED' if duplicate else self.config.auto_error(key,rid)
                if error:
                    yield dict(item,status='BLOCKED',reason=error)
                else:
                    yield dict(item,status='UUID_LOCAL' if key==rid else 'REGISTERED',category='AUTO_LOCAL',repo_key=key)
            elif route and self.config.native_class(route):
                yield dict(item,status='NATIVE_CLASS_PINNED')
            else:
                yield dict(item,status='BLOCKED',reason='INVALID_STORAGE_ROUTE')

    def inspect(self, repo_id, *, lock=False):
        return next(self.inspect_batch([repo_id]))

    def apply_one(self, repo_id, normalize=()):
        # Storage discovery observes native routes. Rewriting a physical binding
        # requires offline migration, never an inventory request.
        if normalize:
            raise ValueError('storage route changes require offline migration')
        return self.inspect(repo_id)

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
            # A registered binding requires no write or second locked scan.
            # Every prospective mutation still revalidates inside apply_one.
            if apply and item['status'] not in ('REGISTERED', 'UUID_LOCAL'):
                item = self.apply_one(item['repo_id'], normalize)
            items.append(item)
        orphans = self.orphans()
        counts = Counter(item['status'] for item in items)
        counts['ORPHAN_DIRECTORY'] += len(orphans)
        if schema_status == 'SCHEMA_MISSING':
            counts['SCHEMA_MISSING'] = 1
        return dict(schema={'status': schema_status}, mode='apply' if apply else 'dry-run', summary=dict(sorted(counts.items())),
                    items=items, orphan_directories=orphans)
