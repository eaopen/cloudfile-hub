"""Sparse extension state. CE lifecycle/authorization must come from the data plane."""

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import hmac
import json
from uuid import UUID, uuid4

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

    def _row(self, reference, evidence, *, locking=False):
        with self.connection.cursor() as cursor:
            self._storage(cursor)
            cursor.execute("SELECT uid,path,lifecycle_ref,revision,description,local_open_type "
                           "FROM cf_resource WHERE repo_id=%s AND path_hash=%s AND kind=%s AND state='active' LIMIT 2" +
                           (" FOR UPDATE" if locking else ""),
                           (reference["repo_id"], self._hash(reference["path"]), reference["kind"]))
            rows = cursor.fetchall()
        if (len(rows) > 1 or any(row[1] != reference["path"] for row in rows) or
                (rows and rows[0][2] != evidence.lifecycle_ref)):
            raise ContractError("PATH_STATE_PENDING", "Resource lifecycle requires reconciliation", 503)
        if not rows:
            return None
        return self._decode_row(reference, rows[0])

    @staticmethod
    def _storage(cursor):
        # Pin table metadata before checking constraints. Missing/prefix/extra
        # index columns cannot satisfy the point-lookup and lifecycle contract.
        cursor.execute("SELECT uid FROM cf_resource LIMIT 0 FOR UPDATE")
        cursor.fetchall()
        cursor.execute("SELECT ENGINE FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='cf_resource'")
        if cursor.fetchall() != (("InnoDB",),):
            raise ContractError("RESOURCE_UNAVAILABLE", "Resource storage requires reconciliation", 503)
        for index, expected in (("PRIMARY", (("uid", 0, None),)),
                ("resource_location", (("repo_id", 1, None), ("path_hash", 1, None), ("kind", 1, None)))):
            cursor.execute("SELECT column_name,non_unique,sub_part FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='cf_resource' AND index_name=%s ORDER BY seq_in_index", (index,))
            if cursor.fetchall() != expected:
                raise ContractError("RESOURCE_UNAVAILABLE", "Resource indexes require reconciliation", 503)

    @staticmethod
    def _decode_row(reference, row):
        """Stored values must satisfy the public contract, not just SQL types."""
        try:
            if len(row) != 6:
                raise ValueError("invalid row shape")
            uid, path, lifecycle, revision, description, hint = row
            if not isinstance(uid, str) or str(UUID(uid)) != uid:
                raise ValueError("invalid resource identity")
            if type(revision) is not int or not 1 <= revision <= 18446744073709551615:
                raise ValueError("invalid resource revision")
            identifier(lifecycle, maximum=512)
            if path != reference["path"]:
                raise ValueError("invalid resource path")
            attributes = {}
            if description is not None:
                attributes["description"] = description
            if hint is not None:
                attributes["local_open_type"] = hint
            if attributes:
                annotation_changes(attributes, kind=reference["kind"])
            return dict(zip(("uid", "path", "lifecycle_ref", "revision", "description", "local_open_type"), row))
        except (ValueError, TypeError, AttributeError, ContractError):
            raise ContractError("RESOURCE_UNAVAILABLE", "Resource state requires reconciliation", 503) from None

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

    def resolve_authorized(self, reference, *, authority, lifecycle_reader, include_tags=False):
        """Same-transaction ordinary read; no earlier inspector boolean grant.

        Trusted lifecycle_reader(cursor, reference) must resolve actual native
        lifecycle under the held authority scope, not synthesize hash/head IDs.
        This method does not create a sparse row for an unannotated resource.
        """
        from ..authorization.read import ContentReadAuthority
        if (not isinstance(authority, ContentReadAuthority) or
                authority.state.connection is not self.connection or not callable(lifecycle_reader) or
                type(include_tags) is not bool):
            raise ValueError("same-connection read authority and lifecycle reader required")
        reference = resource_ref(reference)
        def read(cursor, ref):
            evidence = self._validate_evidence(lifecycle_reader(cursor, ref))
            row = self._row(ref, evidence, locking=True)
            result = self._snapshot(ref, evidence, row)
            access = getattr(authority, "effective_access", None)
            if not isinstance(access, dict) or access.get("read") is not True or type(access.get("write")) is not bool:
                raise ContractError("POLICY_UNAVAILABLE", "Resource access result is unavailable", 503)
            result["access"] = dict(access)
            if include_tags:
                from ..tags.read import bound_tags
                result["tags"] = bound_tags(cursor, resource_uid=row["uid"], repo_id=ref["repo_id"]) if row else []
            return result
        return authority.consume(reference, read)

    def replace_user_tags_authorized(self, reference, tag_ids, *, expected_revision,
                                    authority, lifecycle_reader, request_id, tag_values=None, idempotency_key=None):
        from ..authorization.read import ContentMetadataWriteAuthority
        from ..tags.bindings import replace_user_tags
        from ..tags.definitions import uuid_value
        from ..tags.read import bound_tags
        if (not isinstance(authority, ContentMetadataWriteAuthority) or
                authority.state.connection is not self.connection or not callable(lifecycle_reader)):
            raise ValueError("same-connection native write authority and lifecycle reader required")
        identifier(request_id)
        if not isinstance(tag_ids, list) or len(tag_ids) > 128:
            raise ContractError("INVALID_REQUEST", "Too many resource tags", 400)
        ids = [uuid_value(value) for value in tag_ids]
        if len(ids) != len(set(ids)):
            raise ContractError("INVALID_REQUEST", "Duplicate resource tags", 400)
        reference = resource_ref(reference)
        definitions = None
        if tag_values is not None:
            from ..tags.definitions import user_definition
            if ids or not isinstance(tag_values, list) or len(tag_values) > 128:
                raise ContractError("INVALID_REQUEST", "Invalid resource tag definitions", 400)
            definitions = [user_definition(reference["repo_id"], str(uuid4()), value) for value in tag_values]
            if len({value["normalized_label"] for value in definitions}) != len(definitions):
                raise ContractError("INVALID_REQUEST", "Duplicate resource tag labels", 400)
        def write(cursor, ref):
            evidence = self._validate_evidence(lifecycle_reader(cursor, ref))
            if idempotency_key is not None:
                from .requests import execute
                self._row(ref, evidence, locking=True)
                values = [{"label": value["label"], "color": value["color"]} for value in definitions] if definitions is not None else None
                return execute(cursor, provider=authority.state.provider, actor=authority.actor,
                    operation="tags.values.replace" if definitions is not None else "tags.ids.replace",
                    key=idempotency_key, request=dict(reference=ref, revision=expected_revision,
                        values=values, tag_ids=ids), lifecycle=evidence.lifecycle_ref,
                    secret=self.secret, mutate=lambda: apply(cursor, ref, evidence))
            return apply(cursor, ref, evidence)
        def apply(cursor, ref, evidence):
            row = self._row(ref, evidence, locking=True)
            old = self._snapshot(ref, evidence, row)
            compare_revision(expected_revision, old["revision"])
            target_ids = ids
            if definitions is not None:
                from ..tags.write import create_user
                # Definition creation and binding share the same authority,
                # lifecycle/condition, audit, final epoch check and rollback.
                target_ids = [create_user(cursor, repo_id=ref["repo_id"],
                    value={"label": value["label"], "color": value["color"]},
                    actor=authority.actor, request_id=request_id)[0]["tag_id"] for value in definitions]
            if row is None and not target_ids:
                return {**old, "tags": []}, False
            if row is None:
                row = dict(uid=str(uuid4()), path=ref["path"], lifecycle_ref=evidence.lifecycle_ref,
                    revision=1, description=None, local_open_type=None)
                cursor.execute("INSERT INTO cf_resource(uid,repo_id,kind,path,path_hash,lifecycle_ref,revision,state,updated_at) VALUES(%s,%s,%s,%s,%s,%s,1,'active',UTC_TIMESTAMP(6))",
                    (row["uid"], ref["repo_id"], ref["kind"], ref["path"], self._hash(ref["path"]), evidence.lifecycle_ref))
            revision, changed = replace_user_tags(cursor, reference=ref, resource_uid=row["uid"],
                lifecycle_ref=evidence.lifecycle_ref, expected_revision=row["revision"],
                tag_ids=target_ids, actor=authority.actor, request_id=request_id)
            result = {**self._snapshot(ref, evidence, {**row, "revision": revision}),
                "tags": bound_tags(cursor, resource_uid=row["uid"], repo_id=ref["repo_id"])}
            return result, changed
        return authority.consume(resource_ref(reference), write)

    def replace_user_tags(self, reference, tag_ids, *, expected_revision, actor, request_id):
        """Strong resource condition and first-use UID inside lifecycle guard.

        Existing write_guard must protect actual content-write permission and
        lifecycle until commit; preflight inspection cannot satisfy this contract.
        No system bindings or source identity may be selected through this API.
        """
        from ..tags.bindings import replace_user_tags
        from ..tags.definitions import uuid_value
        from ..tags.read import bound_tags
        reference = resource_ref(reference)
        identifier(actor, maximum=225)
        identifier(request_id)
        if not isinstance(tag_ids, list) or len(tag_ids) > 128:
            raise ContractError("INVALID_REQUEST", "Too many resource tags", 400)
        ids = [uuid_value(value) for value in tag_ids]
        if len(ids) != len(set(ids)):
            raise ContractError("INVALID_REQUEST", "Duplicate resource tags", 400)
        with self.write_guard(reference, actor) as guarded_evidence, self._bucket(reference):
            evidence = self._validate_evidence(guarded_evidence)
            self.connection.begin()
            try:
                row = self._row(reference, evidence, locking=True)
                old = self._snapshot(reference, evidence, row)
                compare_revision(expected_revision, old["revision"])
                if row is None and not ids:
                    self.connection.rollback()
                    return {**old, "tags": []}, False
                if row is None:
                    row = dict(uid=str(uuid4()), path=reference["path"], lifecycle_ref=evidence.lifecycle_ref,
                        revision=1, description=None, local_open_type=None)
                    with self.connection.cursor() as cursor:
                        cursor.execute("INSERT INTO cf_resource(uid,repo_id,kind,path,path_hash,lifecycle_ref,revision,state,updated_at) VALUES(%s,%s,%s,%s,%s,%s,1,'active',UTC_TIMESTAMP(6))",
                            (row["uid"], reference["repo_id"], reference["kind"], reference["path"],
                             self._hash(reference["path"]), evidence.lifecycle_ref))
                with self.connection.cursor() as cursor:
                    revision, changed = replace_user_tags(cursor, reference=reference,
                        resource_uid=row["uid"], lifecycle_ref=evidence.lifecycle_ref,
                        expected_revision=row["revision"], tag_ids=ids, actor=actor, request_id=request_id)
                    tags = bound_tags(cursor, resource_uid=row["uid"], repo_id=reference["repo_id"])
                result = {**self._snapshot(reference, evidence, {**row, "revision": revision}), "tags": tags}
                self.connection.commit()
                return result, changed
            finally:
                self.connection.rollback()

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

    def write_authorized(self, reference, changes, *, expected_revision, authority, lifecycle_reader, idempotency_key=None):
        """Description/open hint mutation in the actual C-authorized transaction.

        Lifecycle reader must use authoritative native evidence on this cursor.
        No earlier RPC or content hash can substitute for object-lifecycle state.
        """
        from ..authorization.read import ContentMetadataWriteAuthority
        if (not isinstance(authority, ContentMetadataWriteAuthority) or
                authority.state.connection is not self.connection or not callable(lifecycle_reader)):
            raise ValueError("same-connection write authority and lifecycle reader required")
        ref = resource_ref(reference)
        changes = annotation_changes(changes, kind=ref["kind"])
        def write(cursor, reference):
            evidence = self._validate_evidence(lifecycle_reader(cursor, reference))
            if idempotency_key is not None:
                from .requests import execute
                self._row(reference, evidence, locking=True)
                return execute(cursor, provider=authority.state.provider, actor=authority.actor,
                    operation="attributes.update", key=idempotency_key,
                    request=dict(reference=reference, changes=changes, revision=expected_revision),
                    lifecycle=evidence.lifecycle_ref, secret=self.secret,
                    mutate=lambda: apply(cursor, reference, evidence))
            return apply(cursor, reference, evidence)
        def apply(cursor, reference, evidence):
            row = self._row(reference, evidence, locking=True)
            old = self._snapshot(reference, evidence, row)
            compare_revision(expected_revision, old["revision"])
            target = {key: changes.get(key, old[key]) for key in ("description", "local_open_type")}
            if all(target[key] == old[key] for key in target):
                return old, False
            created = row is None
            if created:
                row = dict(uid=str(uuid4()), path=reference["path"], lifecycle_ref=evidence.lifecycle_ref,
                    revision=1, **target)
                cursor.execute("INSERT INTO cf_resource(uid,repo_id,kind,path,path_hash,lifecycle_ref,revision,description,local_open_type,state,updated_at) VALUES(%s,%s,%s,%s,%s,%s,1,%s,%s,'active',UTC_TIMESTAMP(6))",
                    (row["uid"], reference["repo_id"], reference["kind"], reference["path"], self._hash(reference["path"]),
                     evidence.lifecycle_ref, target["description"] or None, target["local_open_type"] or None))
            else:
                if type(row["revision"]) is not int or not 1 <= row["revision"] < 2 ** 64 - 1:
                    raise ContractError("PATH_STATE_PENDING", "Resource revision requires reconciliation", 503)
                cursor.execute("UPDATE cf_resource SET description=%s,local_open_type=%s,revision=revision+1,updated_at=UTC_TIMESTAMP(6) WHERE uid=%s AND revision=%s",
                    (target["description"] or None, target["local_open_type"] or None, row["uid"], row["revision"]))
                if cursor.rowcount != 1:
                    raise ContractError("RESOURCE_REVISION_CONFLICT", "Resource has changed", 409)
                row = {**row, **target, "revision": row["revision"] + 1}
            self.mutation_hook(cursor, dict(action="resource.attributes.updated", actor_user_id=authority.actor,
                resource_uid=row["uid"], repo_id=reference["repo_id"], path=reference["path"], revision=str(row["revision"])))
            return self._snapshot(reference, evidence, row), created
        return authority.consume(ref, write)

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
