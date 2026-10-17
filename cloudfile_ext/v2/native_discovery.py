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
                "SELECT t.repo_id,r.repo_id,s.storage_id,c.repo_key,c.state "
                "FROM (SELECT %s AS repo_id) t "
                "LEFT JOIN Repo r ON r.repo_id=t.repo_id "
                "LEFT JOIN RepoStorageId s ON s.repo_id=t.repo_id "
                "LEFT JOIN cf_library_storage c ON c.repo_id=t.repo_id", (repo_id,))
            return self._item(cursor.fetchone())

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
                    "WHERE r.repo_id > %s ORDER BY r.repo_id LIMIT %s",
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
                    "WHERE r.repo_id=%s AND s.repo_id IS NULL",
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

    def summary(self, repo_id=None):
        counts = Counter()
        iterator = (self.inspect(repo_id),) if repo_id else self.scan()
        for item in iterator:
            counts[item["status"]] += 1
        return dict(sorted(counts.items()))
