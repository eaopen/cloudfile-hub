"""Bounded indexed ACL persistence, not an authorization endpoint.

Management authorization must lock its authoritative rows on this cursor.
All mutations share provider/user/repo coordination with native publication.
"""
import hashlib
import json
from datetime import datetime, timezone
from uuid import UUID, uuid4

from ..common.errors import ContractError, invalid
from ..common.conditions import compare_if_match
from ..common.validation import identifier, object_fields
from ..events.outbox import EventWriter
from ..jobs.authority import scope_locks
from ..resources.paths import resource_ref, normalize_path
from ..schema.runner import SchemaRunner


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def rule_value(value):
    object_fields(value, ("path", "kind", "subject", "permission", "inherit"))
    path = normalize_path(value["path"], value["kind"])
    if len(path.encode()) > 4096 or len(path.split("/")) > 130:
        raise invalid("ACL path exceeds budget")
    subject = value["subject"]
    object_fields(subject, ("type", "provider", "namespace", "external_id"))
    if subject["type"] not in {"user", "dept", "group"}:
        raise invalid("Invalid ACL subject type")
    for key, item in subject.items():
        identifier(item, maximum=32 if key == "provider" else 255)
    if subject["type"] == "user" and (len(subject["external_id"]) > 225 or subject["namespace"] != "user"):
        raise invalid("Invalid business user identifier")
    if (not isinstance(value["permission"], str) or
            value["permission"] not in {"invisible", "none", "r", "rw"} or
            type(value["inherit"]) is not bool or
            (value["kind"] == "file" and (value["inherit"] or value["permission"] not in {"invisible", "none"}))):
        raise invalid("Invalid ACL permission or inheritance")
    return {**value, "path": path, "subject": dict(subject)}


class ACLRules:
    FIELDS = "id,repo_id,path,path_hash,kind,subject_type,provider,namespace,external_id,subject_hash,permission,inherit,revision"

    def __init__(self, connection, *, provider, actor, request_id, authorize):
        if not connection.get_autocommit() or not callable(authorize):
            raise ValueError("dedicated connection and transactional management authorization required")
        identifier(provider, maximum=32)
        identifier(actor, maximum=225)
        identifier(request_id)
        SchemaRunner(connection).require_current()
        self.connection, self.provider, self.actor = connection, provider, actor
        self.request_id, self.authorize = request_id, authorize
        self.events = EventWriter()
        self._require_storage()

    def _require_storage(self):
        # Old tables must be explicitly reconciled; CREATE/column presence alone
        # never proves safe indexes, binary identity or an InnoDB transaction.
        expected = {name: ("char", length, "ascii_bin") for name, length in
            (("id", 36), ("repo_id", 36), ("path_hash", 64), ("subject_hash", 64), ("revision", 36))}
        expected.update({name: ("varchar", length, collation) for name, length, collation in
            (("kind", 4, "ascii_bin"), ("subject_type", 8, "ascii_bin"),
             ("permission", 16, "ascii_bin"), ("provider", 32, "utf8mb4_bin"),
             ("namespace", 255, "utf8mb4_bin"), ("external_id", 255, "utf8mb4_bin"))})
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("SELECT ENGINE FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='cf_dir_acl'")
                if cursor.fetchall() != (("InnoDB",),): raise ValueError()
                cursor.execute("SELECT column_name,data_type,character_maximum_length,collation_name,is_nullable FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='cf_dir_acl'")
                columns = {row[0]: row[1:] for row in cursor.fetchall()}
                if any(columns.get(name) != (*shape, "NO") for name, shape in expected.items()):
                    raise ValueError()
                if (columns.get("path", ())[:1] != ("text",) or
                        columns["path"][2:] != ("utf8mb4_bin", "NO") or
                        columns.get("inherit") != ("tinyint", None, None, "NO")):
                    raise ValueError()
                cursor.execute("SELECT index_name,column_name,seq_in_index,sub_part,non_unique FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='cf_dir_acl' ORDER BY index_name,seq_in_index")
                indexes = {}
                for name, column, order, prefix, non_unique in cursor.fetchall():
                    indexes.setdefault(name, []).append((column, order, prefix, non_unique))
                for name, names, unique in (("PRIMARY", ("id",), 0),
                        ("acl_target_subject", ("repo_id", "path_hash", "kind", "subject_hash"), 0),
                        ("acl_ancestors", ("repo_id", "path_hash", "id"), 1)):
                    if indexes.get(name) != [(column, index + 1, None, unique) for index, column in enumerate(names)]:
                        raise ValueError()
        except Exception:
            raise ContractError("POLICY_UNAVAILABLE", "ACL storage requires reconciliation", 503) from None

    @staticmethod
    def _subject_hash(subject):
        return digest(json.dumps(subject, sort_keys=True, ensure_ascii=False, separators=(",", ":")))

    @classmethod
    def _decode(cls, row):
        if len(row) != 13:
            raise ValueError("invalid stored ACL")
        id_, repo, path, path_hash, kind, type_, provider, namespace, external, subject_hash, permission, inherit, revision = row
        if type(inherit) is not int or inherit not in (0, 1):
            raise ValueError("invalid stored inheritance")
        try:
            ref = resource_ref(dict(repo_id=repo, path=path, kind=kind))
            value = rule_value(dict(path=path, kind=kind, subject=dict(type=type_, provider=provider,
                namespace=namespace, external_id=external), permission=permission, inherit=bool(inherit)))
        except ContractError:
            raise ValueError("invalid stored ACL") from None
        if (ref["repo_id"] != repo or ref["path"] != path or len(path.encode()) > 4096 or path_hash != digest(path) or
                subject_hash != cls._subject_hash(value["subject"]) or str(UUID(id_)) != id_ or
                str(UUID(revision)) != revision):
            raise ValueError("invalid stored ACL identity")
        return dict(id=id_, repo_id=repo, **value, revision=revision, etag='"' + revision + '"')

    def candidates(self, reference):
        """Complete ancestor set; no library/file-wide scan, overflow denies."""
        ref = resource_ref(reference)
        if len(ref["path"].encode()) > 4096:
            raise invalid("ACL path is too long")
        paths = ["/"]
        if ref["path"] != "/":
            parts = ref["path"].split("/")[1:]
            if len(parts) > 128:
                raise invalid("ACL path is too deep")
            paths.extend("/" + "/".join(parts[:index]) for index in range(1, len(parts) + 1))
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("SELECT " + self.FIELDS + " FROM cf_dir_acl WHERE repo_id=%s AND path_hash IN (" +
                    ",".join(["%s"] * len(paths)) + ") AND (kind='dir' OR (kind=%s AND path_hash=%s)) ORDER BY path_hash,id LIMIT 4097",
                    (ref["repo_id"], *(digest(path) for path in paths), ref["kind"], digest(ref["path"])))
                rows = cursor.fetchall()
            if len(rows) > 4096:
                raise ValueError("candidate budget exceeded")
            values = [self._decode(row) for row in rows]
            if any(value["path"] not in paths or
                   (value["kind"] == "file" and value["path"] != ref["path"]) for value in values):
                raise ValueError("candidate identity mismatch")
            return values
        except ContractError:
            raise
        except Exception:
            raise ContractError("POLICY_UNAVAILABLE", "ACL rules are unavailable", 503) from None

    def mutate(self, reference, *, value=None, rule_id=None, if_match=None):
        """Create, replace or delete one rule; no implicit management bypass.

        API idempotency registry and delegation remain host service concerns.
        value=None means delete, requiring an existing UUID and strong If-Match.
        """
        ref = resource_ref(reference)
        if len(ref["path"].encode()) > 4096 or len(ref["path"].split("/")) > 130:
            raise invalid("ACL path exceeds budget")
        if value is not None:
            value = rule_value(value)
            if (value["path"], value["kind"]) != (ref["path"], ref["kind"]):
                raise invalid("ACL target mismatch")
        if rule_id is not None:
            try:
                if str(UUID(rule_id)) != rule_id: raise ValueError()
            except (ValueError, TypeError, AttributeError):
                raise invalid("Invalid ACL rule ID") from None
        elif value is None or if_match is not None:
            raise invalid("Invalid ACL mutation")
        scopes = [dict(type="provider", provider=self.provider, external_id=self.provider),
                  dict(type="user", provider=self.provider, external_id=self.actor),
                  dict(type="repo", provider="cloudfile", external_id=ref["repo_id"])]
        try:
            with scope_locks(self.connection, scopes):
                self.connection.begin()
                try:
                    with self.connection.cursor() as cursor:
                        if self.authorize(cursor, self.actor, ref) is not True:
                            raise ContractError("ACCESS_DENIED", "ACL management is not allowed", 403)
                        previous = None
                        if rule_id is not None:
                            cursor.execute("SELECT " + self.FIELDS + " FROM cf_dir_acl WHERE repo_id=%s AND id=%s FOR UPDATE",
                                           (ref["repo_id"], rule_id))
                            rows = cursor.fetchall()
                            if not rows:
                                raise ContractError("NOT_FOUND", "ACL rule does not exist", 404)
                            if len(rows) != 1: raise ValueError()
                            previous = self._decode(rows[0])
                            if (previous["path"], previous["kind"]) != (ref["path"], ref["kind"]):
                                raise ContractError("NOT_FOUND", "ACL rule does not exist", 404)
                            compare_if_match(if_match, previous["etag"])
                        id_ = rule_id or str(uuid4())
                        revision = str(uuid4())
                        if value is None:
                            cursor.execute("DELETE FROM cf_dir_acl WHERE id=%s AND repo_id=%s", (id_, ref["repo_id"]))
                            if cursor.rowcount != 1: raise ValueError()
                            result = dict(id=id_, deleted=True)
                        else:
                            s = value["subject"]
                            fields = (ref["path"], digest(ref["path"]), ref["kind"], s["type"], s["provider"],
                                s["namespace"], s["external_id"], self._subject_hash(s), value["permission"],
                                int(value["inherit"]), revision)
                            if previous is None:
                                cursor.execute("INSERT INTO cf_dir_acl(" + self.FIELDS + ") VALUES(" +
                                    ",".join(["%s"] * 13) + ")", (id_, ref["repo_id"], *fields))
                            else:
                                cursor.execute("UPDATE cf_dir_acl SET path=%s,path_hash=%s,kind=%s,subject_type=%s,provider=%s,namespace=%s,external_id=%s,subject_hash=%s,permission=%s,inherit=%s,revision=%s WHERE id=%s AND repo_id=%s",
                                    (*fields, id_, ref["repo_id"]))
                                if cursor.rowcount != 1: raise ValueError()
                            result = dict(id=id_, repo_id=ref["repo_id"], **value, revision=revision, etag='"' + revision + '"')
                        self.events.append(cursor, dict(event_id=str(uuid4()), request_id=self.request_id,
                            occurred_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                            actor_user_id=self.actor, actor_kind="user", source="hub",
                            action="acl.deleted" if value is None else "acl.updated" if previous else "acl.created",
                            result="succeeded", repo_id=ref["repo_id"], path=ref["path"], policy_revision=revision))
                    self.connection.commit()
                    return result
                finally:
                    self.connection.rollback()
        except ContractError:
            raise
        except Exception as error:
            if error.args and error.args[0] == 1062:
                raise ContractError("RULE_CONFLICT", "ACL rule already exists", 409) from None
            raise ContractError("POLICY_UNAVAILABLE", "ACL mutation is unavailable", 503) from None
