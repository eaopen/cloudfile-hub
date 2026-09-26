"""Sparse extension state. CE lifecycle/authorization must come from the data plane."""

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import hmac
import json
from uuid import uuid4

from ..common.conditions import compare_revision
from ..common.errors import ContractError
from ..common.validation import annotation_changes, identifier
from .paths import resource_ref


@dataclass(frozen=True)
class ResourceEvidence:
    """Stable object-lifecycle evidence, not a content hash or repository head ID."""
    lifecycle_ref: str


class ResourceStore:
    def __init__(self, connection, *, inspector, write_guard, secret, mutation_hook):
        if not connection.get_autocommit():
            raise ValueError("resource store requires its own autocommit connection")
        if not all(callable(value) for value in (inspector, write_guard, mutation_hook)):
            raise ValueError("authoritative inspector, commit guard and transaction event hook are required")
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError("resource validator secret must contain at least 32 bytes")
        self.connection = connection
        self.inspector = inspector
        # The data-plane guard must fence structural/ACL changes until SQL commit.
        # A successful preflight RPC alone cannot protect against delete/recreate races.
        self.write_guard = write_guard
        self.secret = secret
        self.mutation_hook = mutation_hook

    @staticmethod
    def _hash(path):
        return hashlib.sha256(path.encode("utf-8")).hexdigest()

    def _evidence(self, reference, actor, action):
        identifier(actor, maximum=225)
        evidence = self.inspector(reference, actor, action)
        return self._validate_evidence(evidence)

    @staticmethod
    def _validate_evidence(evidence):
        if not isinstance(evidence, ResourceEvidence):
            raise ContractError("PATH_STATE_PENDING", "Resource lifecycle is not ready", 503)
        identifier(evidence.lifecycle_ref, maximum=512)
        return evidence

    def _row(self, reference, evidence):
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT uid,path,lifecycle_ref,revision,description,local_open_type "
                           "FROM cf_resource WHERE repo_id=%s AND path_hash=%s AND kind=%s AND state='active'",
                           (reference["repo_id"], self._hash(reference["path"]), reference["kind"]))
            rows = [row for row in cursor.fetchall() if row[1] == reference["path"]]
        if len(rows) > 1 or (rows and rows[0][2] != evidence.lifecycle_ref):
            raise ContractError("PATH_STATE_PENDING", "Resource lifecycle requires reconciliation", 503)
        if not rows:
            return None
        return dict(zip(("uid", "path", "lifecycle_ref", "revision", "description", "local_open_type"), rows[0]))

    def _snapshot(self, reference, evidence, row):
        payload = json.dumps([reference, evidence.lifecycle_ref,
                              row["uid"] if row else None, row["revision"] if row else 0],
                             ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        revision = "r1-" + hmac.digest(self.secret, payload, "sha256").hex()
        return {"resource": dict(reference), "uid": row["uid"] if row else None,
                "revision": revision, "description": (row["description"] or "") if row else "",
                "local_open_type": (row["local_open_type"] or "") if row else ""}

    def resolve(self, reference, *, actor):
        reference = resource_ref(reference)
        evidence = self._evidence(reference, actor, "read")
        return self._snapshot(reference, evidence, self._row(reference, evidence))

    @contextmanager
    def _bucket(self, reference):
        scope = json.dumps([reference["repo_id"], reference["kind"], self._hash(reference["path"])])
        name = "cf.resource." + hashlib.sha256(scope.encode()).hexdigest()[:48]
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT GET_LOCK(%s,5)", (name,))
            if cursor.fetchone()[0] != 1:
                raise ContractError("RESOURCE_BUSY", "Resource is busy", 503)
        try:
            yield
        finally:
            self.connection.rollback()
            with self.connection.cursor() as cursor:
                cursor.execute("SELECT RELEASE_LOCK(%s)", (name,))

    def write(self, reference, changes, *, expected_revision, actor):
        reference = resource_ref(reference)
        changes = annotation_changes(changes, kind=reference["kind"])
        identifier(actor, maximum=225)
        # Always acquire the data-plane guard before the SQL bucket. Server callers
        # must use this same lock order; the guard remains held through commit.
        with self.write_guard(reference, actor) as guarded_evidence, self._bucket(reference):
            evidence = self._validate_evidence(guarded_evidence)
            self.connection.begin()
            row = self._row(reference, evidence)
            old = self._snapshot(reference, evidence, row)
            compare_revision(expected_revision, old["revision"])
            target = {key: changes.get(key, old[key]) for key in ("description", "local_open_type")}
            if all(target[key] == old[key] for key in target):
                self.connection.rollback()
                return old, False
            created = row is None
            if created:
                row = {"uid": str(uuid4()), "path": reference["path"], "lifecycle_ref": evidence.lifecycle_ref,
                       "revision": 1, **target}
                with self.connection.cursor() as cursor:
                    cursor.execute("INSERT INTO cf_resource(uid,repo_id,kind,path,path_hash,lifecycle_ref,"
                                   "revision,description,local_open_type,state,updated_at) "
                                   "VALUES(%s,%s,%s,%s,%s,%s,1,%s,%s,'active',UTC_TIMESTAMP(6))",
                                   (row["uid"], reference["repo_id"], reference["kind"], reference["path"],
                                    self._hash(reference["path"]), evidence.lifecycle_ref,
                                    target["description"] or None, target["local_open_type"] or None))
            else:
                with self.connection.cursor() as cursor:
                    cursor.execute("UPDATE cf_resource SET description=%s,local_open_type=%s,"
                                   "revision=revision+1,updated_at=UTC_TIMESTAMP(6) WHERE uid=%s AND revision=%s",
                                   (target["description"] or None, target["local_open_type"] or None,
                                    row["uid"], row["revision"]))
                    if cursor.rowcount != 1:
                        raise ContractError("RESOURCE_REVISION_CONFLICT", "Resource has changed", 409)
                row = {**row, **target, "revision": row["revision"] + 1}
            event = {"action": "resource.attributes.updated", "actor_user_id": actor,
                     "resource_uid": row["uid"], "repo_id": reference["repo_id"],
                     "path": reference["path"], "revision": str(row["revision"])}
            with self.connection.cursor() as cursor:
                self.mutation_hook(cursor, event)
            self.connection.commit()
            return self._snapshot(reference, evidence, row), created
