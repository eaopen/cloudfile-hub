"""Explicit MySQL/MariaDB DDL with per-step verification, not fictitious rollback."""

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import re
from pathlib import Path


class MigrationError(RuntimeError):
    pass


@dataclass(frozen=True)
class Migration:
    version: str
    steps: tuple

    def __post_init__(self):
        if (not isinstance(self.version, str) or
                not re.fullmatch(r"[0-9]{3}_[a-z][a-z0-9_]{0,59}", self.version) or
                not isinstance(self.steps, tuple) or not self.steps):
            raise MigrationError("invalid migration definition")
        for step in self.steps:
            if (not isinstance(step, dict) or set(step) != {"sql", "verify", "expected"} or
                    not isinstance(step["sql"], str) or not step["sql"] or
                    not isinstance(step["verify"], str) or not step["verify"] or
                    type(step["expected"]) is not int):
                raise MigrationError("invalid migration step")

    @property
    def checksum(self):
        payload = json.dumps({"version": self.version, "steps": self.steps},
                             sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode()).hexdigest()


def load_migrations(directory=None):
    directory = Path(__file__).with_name("migrations") if directory is None else Path(directory)
    migrations = []
    for path in sorted(directory.glob("*.json")):
        value = json.loads(path.read_text(encoding="utf-8"))
        if (set(value) != {"version", "steps"} or not isinstance(value["version"], str) or
                not value["version"] or not isinstance(value["steps"], list) or not value["steps"]):
            raise MigrationError("invalid migration definition")
        for step in value["steps"]:
            if (not isinstance(step, dict) or set(step) != {"sql", "verify", "expected"} or
                    not isinstance(step["sql"], str) or not isinstance(step["verify"], str) or
                    type(step["expected"]) is not int):
                raise MigrationError("invalid migration step")
        migrations.append(Migration(value["version"], tuple(value["steps"])))
    if len({item.version for item in migrations}) != len(migrations):
        raise MigrationError("duplicate migration version")
    return tuple(migrations)


class SchemaRunner:
    def __init__(self, connection, migrations=None, *, profile=None):
        if not connection.get_autocommit():
            raise MigrationError("schema runner requires a dedicated autocommit connection")
        self.connection = connection
        self.offline = False
        if profile not in (None, "legacy", "m1") or (migrations is not None and profile is not None):
            raise MigrationError("invalid schema profile")
        self.profile = "custom" if migrations is not None else profile
        if self.profile is None:
            self.profile = "legacy"
            if self._exists() and self._query("SELECT version FROM cf_schema_migration WHERE version='100_m1_storage'"):
                self.profile = "m1"
        if self.profile == "m1":
            from .m1 import migrations as m1_migrations
            self.migrations = m1_migrations()
        else:
            self.migrations = load_migrations() if migrations is None else tuple(migrations)
        if len({item.version for item in self.migrations}) != len(self.migrations):
            raise MigrationError("duplicate migration version")

    def _query(self, sql, parameters=()):
        with self.connection.cursor() as cursor:
            cursor.execute(sql, parameters if parameters else None)
            return cursor.fetchall() if cursor.description is not None else ()

    @contextmanager
    def _locked(self):
        acquired = self._query("SELECT GET_LOCK('cloudfile.schema.v1', 0)")
        if not acquired or acquired[0][0] != 1:
            raise MigrationError("another schema runner is active")
        try:
            yield
        finally:
            self.connection.rollback()
            self._query("SELECT RELEASE_LOCK('cloudfile.schema.v1')")

    def _exists(self):
        return self._query("SELECT COUNT(*) FROM information_schema.tables "
                           "WHERE table_schema=DATABASE() AND table_name='cf_schema_migration'")[0][0] == 1

    def _bootstrap(self):
        if not self._exists():
            self._query("CREATE TABLE cf_schema_migration ("
                        "version VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,"
                        "checksum CHAR(64) CHARACTER SET ascii NOT NULL,"
                        "state VARCHAR(16) NOT NULL,step INT NOT NULL DEFAULT 0,"
                        "started_at DATETIME(6) NOT NULL,finished_at DATETIME(6) NULL,"
                        "error_code VARCHAR(64) NULL) ENGINE=InnoDB")
            self.connection.commit()
        columns = self._query("SELECT column_name FROM information_schema.columns "
                              "WHERE table_schema=DATABASE() AND table_name='cf_schema_migration'")
        if {row[0] for row in columns} != {
            "version", "checksum", "state", "step", "started_at", "finished_at", "error_code",
        }:
            raise MigrationError("migration ledger structure is not supported")

    def status(self):
        if not self._exists():
            return []
        rows = self._query("SELECT version,checksum,state,step,error_code "
                           "FROM cf_schema_migration ORDER BY version")
        return [dict(zip(("version", "checksum", "state", "step", "error_code"), row)) for row in rows]

    def plan(self):
        existing = {row["version"]: row for row in self.status()}
        versions = {migration.version for migration in self.migrations}
        if set(existing) - versions:
            raise MigrationError("database contains unknown migration versions")
        result = []
        for migration in self.migrations:
            row = existing.get(migration.version)
            if row is not None and row["checksum"] != migration.checksum:
                raise MigrationError("applied or attempted migration checksum changed")
            if row is not None and (
                    row["state"] not in {"running", "failed", "applied"} or
                    not 0 <= row["step"] <= len(migration.steps) or
                    (row["state"] == "applied" and row["step"] != len(migration.steps))):
                raise MigrationError("migration ledger state is not supported")
            result.append({"version": migration.version, "checksum": migration.checksum,
                           "state": row["state"] if row else "pending",
                           "step": row["step"] if row else 0})
        return result

    def apply(self):
        with self._locked():
            if self.profile == "m1":
                from .m1 import preflight
                preflight(self)
            self._check_directory_layouts(upgrading=True)
            self._bootstrap()
            plan = {item["version"]: item for item in self.plan()}
            for migration in self.migrations:
                self._apply_one(migration, plan[migration.version])
            self.require_current()
        return self.status()

    def _check_directory_layouts(self, *, upgrading=False):
        if self.profile == "m1":
            return
        # CREATE IF NOT EXISTS would hide legacy/type drift. Reject it before
        # applying any unrelated DDL; the explicit offline directory upgrade
        # is the only operation allowed to archive old directory tables.
        from .directory import VERSIONS, inspect_tables
        if VERSIONS.intersection(m.version for m in self.migrations):
            allowed = ('missing', 'current', 'v09') if upgrading or not any(m.version == '042_unified_directory_acl' for m in self.migrations) else ('missing', 'current')
            if any(row['state'] not in allowed for row in inspect_tables(self)):
                raise MigrationError('directory schema is incompatible; run directory-plan before offline upgrade')
            if upgrading and any(m.version == '042_unified_directory_acl' for m in self.migrations):
                # Existing installations must stop both Hub and native writers;
                # a new empty database is allowed to run the full catalog directly.
                if not self.offline and self._query("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='cf_dir_share'")[0][0]:
                    raise MigrationError('existing sharing requires directory-apply --offline')

    def _verify(self, step):
        sql = step["verify"]
        # Migration 042 retires the independent table. Preserve 040's immutable
        # checksum while verifying its explicit successor, never recreate it.
        if "table_name='cf_dir_share'" in sql and sql.startswith("SELECT IF("):
            if self._exists():
                successor = self._query("SELECT state,step FROM cf_schema_migration WHERE version='042_unified_directory_acl'")
                if successor and successor[0][1] >= 2 and not self._query(
                        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='cf_dir_share'")[0][0]:
                    from .unified_acl import successor_steps
                    return all(self._verify(item) for item in successor_steps())
        rows = self._query(sql)
        return len(rows) == 1 and len(rows[0]) == 1 and rows[0][0] == step["expected"]

    def _apply_one(self, migration, previous):
        if previous["state"] == "applied":
            if not all(self._verify(step) for step in migration.steps):
                raise MigrationError("applied migration structure has drifted")
            return
        self._query("INSERT INTO cf_schema_migration(version,checksum,state,step,started_at) "
                    "VALUES(%s,%s,'running',0,UTC_TIMESTAMP(6)) "
                    "ON DUPLICATE KEY UPDATE state='running',error_code=NULL,finished_at=NULL",
                    (migration.version, migration.checksum))
        self.connection.commit()
        try:
            for index, step in enumerate(migration.steps, 1):
                # DDL may have committed before a crash. Verify actual structure before replay.
                if not self._verify(step):
                    # Retired independent sharing was never enabled. Version
                    # 042 drops the table without importing old grants.
                    self._query(step["sql"])
                    self.connection.commit()
                if not self._verify(step):
                    raise MigrationError("migration step did not establish the expected structure")
                self._query("UPDATE cf_schema_migration SET step=%s WHERE version=%s", (index, migration.version))
                self.connection.commit()
            self._query("UPDATE cf_schema_migration SET state='applied',finished_at=UTC_TIMESTAMP(6) "
                        "WHERE version=%s", (migration.version,))
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            self._query("UPDATE cf_schema_migration SET state='failed',error_code='MIGRATION_STEP_FAILED' "
                        "WHERE version=%s", (migration.version,))
            self.connection.commit()
            # Do not serialize SQL/connection exceptions: they can include private values.
            raise MigrationError("migration failed; inspect the ledger and repair before retry") from None

    def require_current(self):
        self._check_directory_layouts()
        plan = self.plan()
        if any(item["state"] != "applied" for item in plan):
            raise MigrationError("schema upgrade is required")
        if not all(self._verify(step) for migration in self.migrations for step in migration.steps):
            raise MigrationError("schema structure has drifted")
        if self.profile == "m1":
            from .m1 import require_layout
            require_layout(self)
            return
        from .directory import VERSIONS, verify_indexes
        if VERSIONS.issubset(m.version for m in self.migrations) and not verify_indexes(self):
            raise MigrationError('directory index contract has drifted')
