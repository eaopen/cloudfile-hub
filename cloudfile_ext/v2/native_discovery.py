"""Discover original Seafile repositories and register native path metadata only.

Repo, RepoStorageId and existing CloudFile rows remain authoritative. Nothing
copies bytes, changes ownership, or allocates a new repository UUID.
"""
from collections import Counter
from uuid import UUID


def native_key(repo_id):
    if not isinstance(repo_id, str):
        return None
    try:
        if str(UUID(repo_id)) != repo_id:
            return None
    except (ValueError, AttributeError):
        return None
    return "native-" + repo_id


def classify(repo_id, present, route, key, state):
    """Return a user-facing repair state, never silently adopt routed storage."""
    if not present:
        return "NATIVE_RESOURCE_MISSING"
    marker = native_key(repo_id)
    if marker is None:
        return "INVALID_NATIVE_REPO_ID"
    if route is None and key is None:
        return "NATIVE_UNREGISTERED"
    if route is None and key == marker and state in ("active", "retired"):
        return "NATIVE_REGISTERED"
    if route is not None and route.startswith("auto-local:"):
        if key and route == "auto-local:" + key and state in ("reserved", "active", "retired"):
            return "V2_ROUTED"
        return "STORAGE_BINDING_INCOMPLETE"
    if route is not None and key is None:
        return "EXTERNAL_STORAGE_REQUIRES_REVIEW"
    return "STORAGE_BINDING_CONFLICT"


class NativeLibraryDiscovery:
    """Bounded, repeatable scan of the *current* Seafile database.

    Never enumerate a remote/old database and attach its UUID to the current
    database: the actual Seafile Repo/Commit/FS/Block facts must first exist.
    """

    def __init__(self, connection):
        self.connection = connection

    @staticmethod
    def check_native_schema(connection):
        with connection.cursor() as cursor:
            cursor.execute("SELECT table_name FROM information_schema.tables "
                           "WHERE table_schema=DATABASE() AND table_name IN "
                           "('Repo','Branch','RepoStorageId')")
            present = {row[0] for row in cursor.fetchall()}
        if present != {"Repo", "Branch", "RepoStorageId"}:
            raise RuntimeError("NATIVE_SEAFILE_DATABASE_NOT_CONNECTED")

    @staticmethod
    def _item(row):
        repo_id, present, route, key, state = row
        return {"repo_id": repo_id,
                "status": classify(repo_id, present is not None, route, key, state)}

    def inspect(self, repo_id):
        if native_key(repo_id) is None:
            raise ValueError("repo_id must be a canonical UUID")
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT t.repo_id,r.repo_id,s.storage_id,c.repo_key,c.state,v.repo_id "
                "FROM (SELECT %s AS repo_id) t "
                "LEFT JOIN Repo r ON r.repo_id=t.repo_id "
                "LEFT JOIN RepoStorageId s ON s.repo_id=t.repo_id "
                "LEFT JOIN cf_library_storage c ON c.repo_id=t.repo_id "
                "LEFT JOIN VirtualRepo v ON v.repo_id=t.repo_id", (repo_id,))
            row = cursor.fetchone()
            if row[5] is not None:
                return {"repo_id": repo_id, "status": "VIRTUAL_REPO"}
            return self._item(row[:5])

    def scan(self, batch_size=500):
        if not (1 <= batch_size <= 2000):
            raise ValueError("batch_size out of range")
        last = ""
        while True:
            with self.connection.cursor() as cursor:
                cursor.execute(
                    "SELECT r.repo_id,r.repo_id,s.storage_id,c.repo_key,c.state "
                    "FROM Repo r LEFT JOIN RepoStorageId s ON s.repo_id=r.repo_id "
                    "LEFT JOIN cf_library_storage c ON c.repo_id=r.repo_id "
                    "LEFT JOIN VirtualRepo v ON v.repo_id=r.repo_id "
                    "WHERE r.repo_id > %s AND v.repo_id IS NULL ORDER BY r.repo_id LIMIT %s",
                    (last, batch_size))
                rows = cursor.fetchall()
            if not rows:
                break
            for row in rows:
                yield self._item(row)
            last = rows[-1][0]

    def register_native(self, repo_id):
        # This INSERT SELECT explicitly rechecks the native Repo and route in
        # the same statement, and a concurrent worker cannot overwrite rows.
        before = self.inspect(repo_id)
        if before["status"] != "NATIVE_UNREGISTERED":
            return before
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO cf_library_storage(repo_key,repo_id,state) "
                    "SELECT %s,r.repo_id,'active' FROM Repo r "
                    "LEFT JOIN RepoStorageId s ON s.repo_id=r.repo_id "
                    "LEFT JOIN VirtualRepo v ON v.repo_id=r.repo_id "
                    "WHERE r.repo_id=%s AND s.repo_id IS NULL AND v.repo_id IS NULL",
                    (native_key(repo_id), repo_id))
        except Exception as error:
            # Concurrent reconciliations can hit the unique key; another
            # worker's existing row is never changed or silently overwritten.
            if not getattr(error, "args", ()) or error.args[0] != 1062:
                raise
        return self.inspect(repo_id)

    def reconcile(self, repo_id=None):
        counts = Counter()
        iterator = (self.inspect(repo_id),) if repo_id else self.scan()
        for item in iterator:
            if item["status"] == "NATIVE_UNREGISTERED":
                item = self.register_native(item["repo_id"])
            counts[item["status"]] += 1
        return dict(sorted(counts.items()))

    def unresolved_registry_count(self):
        """Orphan diagnostics only: never retire or delete a record automatically.

        RepoTrash and GarbageRepos are normal native lifecycle locations.
        """
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT COUNT(*) FROM cf_library_storage c "
                "LEFT JOIN Repo r ON r.repo_id=c.repo_id "
                "LEFT JOIN RepoTrash t ON t.repo_id=c.repo_id "
                "LEFT JOIN GarbageRepos g ON g.repo_id=c.repo_id "
                "WHERE r.repo_id IS NULL AND t.repo_id IS NULL "
                "AND g.repo_id IS NULL AND c.state <> 'retired'")
            return cursor.fetchone()[0]

    def summary(self, repo_id=None):
        counts = Counter()
        iterator = (self.inspect(repo_id),) if repo_id else self.scan()
        for item in iterator:
            counts[item["status"]] += 1
        return dict(sorted(counts.items()))

def storage_catalog_status(repo_id, repo_present, key, state, storage_id, readable, *, in_trash=False, in_gc=False, virtual=False):
    """Distinguish a missing registration from a missing native Repo.

    A registry entry alone is not proof that the native object tree is healthy.
    Actual object-byte validation remains a separate FSCK/read test.
    """
    if not repo_present:
        if in_trash:
            return "IN_TRASH"
        if in_gc:
            return "GC_PENDING"
        if key is not None and state == "retired":
            return "RETIRED"
        return "REPO_MISSING"
    if virtual:
        return "VIRTUAL_REPO"
    if key is None:
        return "REGISTRATION_MISSING"
    if state == "retired":
        return "RETIRED"
    if state == "reserved":
        return "RESERVED"
    if state != "active":
        return "BINDING_ERROR"
    native = key == native_key(repo_id) and storage_id is None
    routed = storage_id == "auto-local:" + key and key != native_key(repo_id)
    if not (native or routed):
        return "BINDING_ERROR"
    return "READY" if readable else "RESOURCE_UNREADABLE"

def reconcile_from_hub(repo_id=None, *, batch_size=500):
    """Idempotent native Repo -> cf_library_storage reconciliation from Seahub.

    This uses the current Seafile schema through Django's existing connection,
    not a second set of DB credentials. Etech and the native create endpoint
    share the same guarded insertion, and existing V2 auto-local mappings win.
    """
    from django.db import connection, IntegrityError
    from seahub.utils.db_api import SeafileDB
    from .schema import identifier

    schema = identifier(SeafileDB().db_name)
    repo = schema + '.Repo'
    routes = schema + '.RepoStorageId'
    virtual = schema + '.VirtualRepo'
    registry = schema + '.cf_library_storage'
    if repo_id is not None and native_key(repo_id) is None:
        raise ValueError('Invalid canonical Repo UUID')
    added = 0
    already = 0
    after = ''
    while True:
        with connection.cursor() as cursor:
            if repo_id:
                cursor.execute(
                    'SELECT r.repo_id FROM ' + repo + ' r '
                    'LEFT JOIN ' + virtual + ' v ON v.repo_id=r.repo_id '
                    'WHERE r.repo_id=%s AND v.repo_id IS NULL', [repo_id])
            else:
                cursor.execute(
                    'SELECT r.repo_id FROM ' + repo + ' r '
                    'LEFT JOIN ' + virtual + ' v ON v.repo_id=r.repo_id '
                    'WHERE r.repo_id>%s AND v.repo_id IS NULL '
                    'ORDER BY r.repo_id LIMIT %s', [after, batch_size])
            ids = [row[0] for row in cursor.fetchall()]
        if not ids:
            break
        for native_id in ids:
            if native_key(native_id) is None:
                continue
            # The query decides the route at write time. New routed repos,
            # tombstones, and existing business bindings are NEVER changed.
            with connection.cursor() as cursor:
                try:
                    cursor.execute(
                        'INSERT INTO ' + registry + ' (repo_key,repo_id,state) '
                        "SELECT %s,r.repo_id,'active' FROM " + repo + ' r '
                        'LEFT JOIN ' + routes + ' s ON s.repo_id=r.repo_id '
                        'LEFT JOIN ' + virtual + ' v ON v.repo_id=r.repo_id '
                        'LEFT JOIN ' + registry + ' c ON c.repo_id=r.repo_id '
                        'WHERE r.repo_id=%s AND s.repo_id IS NULL '
                        'AND v.repo_id IS NULL AND c.repo_id IS NULL',
                        ['native-' + native_id, native_id])
                    added += cursor.rowcount
                except IntegrityError as exc:
                    if getattr(exc, 'args', (None,))[0] != 1062:
                        raise
                    # Another instance inserted the same UUID concurrently.
                    cursor.execute('SELECT 1 FROM ' + registry + ' WHERE repo_id=%s', [native_id])
                    if cursor.fetchone() is None:
                        raise
                    already += 1
        after = ids[-1]
        if repo_id or len(ids) < batch_size:
            break
    return {'registered': added, 'already': already}


def inspect_from_hub(repo_ids):
    """One exact native lookup per bounded batch, including missing Repo IDs."""
    from django.db import connection
    from seahub.utils.db_api import SeafileDB
    from .schema import identifier
    schema = identifier(SeafileDB().db_name)
    def table(name):
        return schema + '.' + identifier(name)

    result = {}
    for offset in range(0, len(repo_ids), 200):
        batch = repo_ids[offset:offset + 200]
        if any(native_key(x) is None for x in batch):
            raise ValueError('Invalid Repo UUID')
        if not batch:
            continue
        keys = ' UNION ALL '.join('SELECT %s AS repo_id' for _ in batch)
        sql = ('SELECT i.repo_id,r.repo_id,c.repo_key,c.state,s.storage_id,'
               't.repo_id,g.repo_id,v.repo_id FROM (' + keys + ') i '
               'LEFT JOIN ' + table('Repo') + ' r ON r.repo_id=i.repo_id '
               'LEFT JOIN ' + table('cf_library_storage') + ' c ON c.repo_id=i.repo_id '
               'LEFT JOIN ' + table('RepoStorageId') + ' s ON s.repo_id=i.repo_id '
               'LEFT JOIN ' + table('RepoTrash') + ' t ON t.repo_id=i.repo_id '
               'LEFT JOIN ' + table('GarbageRepos') + ' g ON g.repo_id=i.repo_id '
               'LEFT JOIN ' + table('VirtualRepo') + ' v ON v.repo_id=i.repo_id')
        with connection.cursor() as cursor:
            cursor.execute(sql, batch)
            rows = cursor.fetchall()
        for repo_id, present, key, state, route, trash, garbage, virtual in rows:
            status = storage_catalog_status(
                repo_id, present is not None, key, state, route,
                present is not None, in_trash=trash is not None,
                in_gc=garbage is not None, virtual=virtual is not None)
            result[repo_id] = {
                'status': status,
                'source': 'native' if key == 'native-' + repo_id
                else ('v2' if route and route.startswith('auto-local:') else 'unknown')
            }
    return result
