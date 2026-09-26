"""Append audit facts and outbox on the caller's existing SQL transaction."""

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import re
from uuid import UUID, uuid4

from ..common.errors import ContractError
from ..common.validation import identifier, object_fields, utc_time, sequence
from ..resources.paths import normalize_path


RESULTS = frozenset({"attempted", "succeeded", "denied", "failed", "interrupted", "stream_started", "stream_completed"})
SOURCES = frozenset({"hub", "server", "fileserver", "webdav", "idp", "directory", "worker"})


def normalize_event(event):
    object_fields(event, ("event_id", "occurred_at", "request_id", "actor_user_id", "actor_kind", "source", "action", "result"),
                  ("repo_id", "path", "target_path", "resource_uid", "resource_kind", "job_id", "device_id", "session_id", "delegator", "revision", "content_version", "subject_revision", "policy_revision", "bytes_sent", "target_user_id", "reason"))
    value = dict(event)
    try:
        value["event_id"] = str(UUID(value["event_id"]))
        if value.get("repo_id"):
            value["repo_id"] = str(UUID(value["repo_id"]))
        if value.get("resource_uid"):
            value["resource_uid"] = str(UUID(value["resource_uid"]))
        if value.get("job_id"):
            value["job_id"] = str(UUID(value["job_id"]))
        if "device_id" in value:
            if not isinstance(value["device_id"], str) or str(UUID(value["device_id"])) != value["device_id"]:
                raise ValueError()
        if "session_id" in value:
            if not isinstance(value["session_id"], str) or str(UUID(value["session_id"])) != value["session_id"]:
                raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise ContractError("INVALID_REQUEST", "Invalid event identity", 400) from None
    utc_time(value["occurred_at"])
    identifier(value["request_id"])
    identifier(value["actor_user_id"])
    if value["actor_kind"] not in {"user", "service"} or value["source"] not in SOURCES or value["result"] not in RESULTS:
        raise ContractError("INVALID_REQUEST", "Invalid event origin or result", 400)
    if not isinstance(value["action"], str) or not re.fullmatch(r"[a-z][a-z0-9._-]{0,31}", value["action"]):
        raise ContractError("INVALID_REQUEST", "Invalid event action", 400)
    if "resource_kind" in value and (value["resource_kind"] not in {"file", "dir"} or not value.get("repo_id")):
        raise ContractError("INVALID_REQUEST", "Invalid event resource kind", 400)
    for field in ("path", "target_path"):
        if field in value:
            if not value.get("repo_id"):
                raise ContractError("INVALID_REQUEST", "Event path requires a repository", 400)
            value[field] = normalize_path(value[field], value.get("resource_kind", "dir"))
    for field in ("delegator", "revision", "content_version", "subject_revision", "policy_revision"):
        if field in value:
            identifier(value[field])
    if "target_user_id" in value:
        identifier(value["target_user_id"], maximum=225)
    if "reason" in value:
        reason = value["reason"]
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 512 or any(ord(char) < 32 for char in reason):
            raise ContractError("INVALID_REQUEST", "Invalid audit reason", 400)
    if "bytes_sent" in value and (type(value["bytes_sent"]) is not int or not 0 <= value["bytes_sent"] <= 2 ** 63 - 1):
        raise ContractError("INVALID_REQUEST", "Invalid transfer byte count", 400)
    return value


def projection_required(value):
    """Shared disposition of a normalized immutable audit fact."""
    # Actual JobStore transition records contain only scheduling identity/scope.
    # Completing a job does NOT prove its resource changes indexed: handlers
    # must emit those separate mutation facts in their effect transactions.
    job_shapes = {"job.accepted": ("hub", "attempted"), "job.cancelled": ("hub", "succeeded"),
        "job.retried": ("hub", "succeeded"), "job.completed": ("worker", "succeeded"),
        "job.failed": ("worker", "failed")}
    job_fields = {"event_id", "occurred_at", "request_id", "job_id", "actor_user_id", "actor_kind", "source", "action", "result"}
    if (value.get("action") in job_shapes and
            (value.get("source"), value.get("result")) == job_shapes[value["action"]] and
            set(value) in (job_fields, job_fields | {"repo_id"}) and value.get("request_id") == value.get("job_id") and
            value.get("actor_kind") in {"user", "service"} and
            (value["source"] != "worker" or value["actor_kind"] == "service")):
        try:
            if str(UUID(value["job_id"])) == value["job_id"]:
                return False
        except (ValueError, TypeError, AttributeError):
            pass
    if value["source"] == "hub":
        session_fields = {"event_id", "occurred_at", "request_id", "actor_user_id", "actor_kind", "source",
            "action", "result", "session_id", "device_id", "repo_id", "path", "resource_kind", "resource_uid",
            "revision", "content_version"}
        if (set(value) == session_fields and value["actor_kind"] == "user" and value["result"] == "succeeded"
                and value["action"] in {"local.session.created", "local.session.claimed"}
                and value["resource_kind"] == "file" and re.fullmatch(r"[0-9a-f]{40}", value["content_version"])
                and re.fullmatch(r"[1-9][0-9]{0,19}", value["revision"]) and int(value["revision"]) <= 2 ** 64 - 1):
            return False
        device_fields = {"event_id", "occurred_at", "request_id", "actor_user_id", "actor_kind", "source",
            "action", "result", "device_id", "revision"}
        if (set(value) == device_fields and value["actor_kind"] == "user" and value["result"] == "succeeded"
                and value["action"] in {"device.pair.started", "device.paired", "device.revoked"}):
            revision = value["revision"]
            if isinstance(revision, str) and re.fullmatch(r"[1-9][0-9]{0,19}", revision) and int(revision) <= 2 ** 64 - 1:
                return False
        lock_fields = {"event_id", "occurred_at", "request_id", "actor_user_id", "actor_kind", "source",
            "action", "result", "repo_id", "path", "resource_uid", "resource_kind", "revision"}
        lock_fact = (set(value) == lock_fields and value["action"] in {"lock.acquired", "lock.renewed", "lock.released"})
        lock_recovery = (set(value) == lock_fields | {"reason"} and value["action"] == "lock.force-released" and
            isinstance(value.get("reason"), str) and bool(value["reason"].strip()) and len(value["reason"]) <= 512 and
            not any(ord(char) < 32 for char in value["reason"]))
        if ((lock_fact or lock_recovery)
                and value["actor_kind"] == "user" and value["result"] == "succeeded" and
                value["resource_kind"] == "file" and value.get("repo_id") and value.get("path") and value.get("resource_uid")):
            revision = value.get("revision")
            if isinstance(revision, str) and re.fullmatch(r"[1-9][0-9]{0,19}", revision) and int(revision) <= 2 ** 64 - 1:
                return False
        # These exact producer facts change authorization only. Query-time CE/C
        # guards still enforce the new rules; stream watermarks invalidate old
        # cursors. No file metadata or index ACL is materialized from this fact.
        policy_fields = {"event_id", "occurred_at", "request_id", "actor_user_id", "actor_kind",
            "source", "action", "result", "repo_id", "path", "resource_kind", "policy_revision"}
        if (value["action"] in {"acl.created", "acl.updated", "acl.deleted", "admin.created", "admin.updated", "admin.deleted"}
                and set(value) == policy_fields and value["actor_kind"] == "user"
                and value["result"] == "succeeded" and value.get("repo_id") and value.get("path")
                and value.get("resource_kind") in {"file", "dir"}):
            try:
                if str(UUID(value["policy_revision"])) == value["policy_revision"]:
                    return False
            except (ValueError, TypeError, AttributeError):
                pass
        if (value["action"] == "identity.logout.sessions" and value.get("result") == "succeeded" and
                value.get("actor_kind") == "service" and value.get("job_id") and
                not any(value.get(key) for key in ("repo_id", "path", "target_path", "resource_uid", "resource_kind"))):
            return False
        if (value["action"] == "identity.bound" and value.get("result") == "succeeded" and
                value.get("target_user_id") and not any(value.get(key) for key in ("repo_id", "path", "target_path", "resource_uid", "resource_kind"))):
            return False
        if (value["action"] == "user.delegation.issue" and value.get("result") == "succeeded" and
                value.get("repo_id") and value.get("path") and value.get("resource_kind") == "file" and
                value.get("target_user_id") and value.get("subject_revision") and
                not any(value.get(key) for key in ("target_path", "resource_uid"))):
            return False
        if (value["action"] == "audit.export.download" and value.get("result") == "attempted" and
                value.get("repo_id") and value.get("job_id") and
                not any(value.get(key) for key in ("path", "target_path", "resource_uid", "resource_kind"))):
            return False
    if (value["source"] == "fileserver" and value["action"] in {"file.view", "file.download"} and
            value.get("resource_kind") == "file"):
        return False
    if (value["source"] == "hub" and value["action"] == "tags.definition.created" and value["result"] == "succeeded" and
            isinstance(value.get("reason"), str) and value["reason"].startswith("tag_id:") and
            not value.get("path") and not value.get("target_path")):
        try:
            return str(UUID(value["reason"][7:])) != value["reason"][7:]
        except (ValueError, AttributeError):
            pass
    return True


class EventWriter:
    def append(self, cursor, event):
        # Caller owns commit/rollback. A hook on a different connection is forbidden.
        value = normalize_event(event)
        # MySQL/MariaDB accept SAVEPOINT outside a transaction but cannot RELEASE
        # that nonexistent savepoint. Verify before any durable write, without
        # starting/committing a transaction owned by somebody else.
        savepoint = "cf_event_" + uuid4().hex
        try:
            cursor.execute("SAVEPOINT " + savepoint)
            cursor.execute("RELEASE SAVEPOINT " + savepoint)
        except Exception:
            raise RuntimeError("event append requires an active SQL transaction") from None
        stream = "repo." + value["repo_id"] if value.get("repo_id") else "security"
        cursor.execute("SELECT payload FROM cf_event_outbox WHERE event_id=%s", (value["event_id"],))
        existing = cursor.fetchone()
        if existing:
            prior = json.loads(existing[0])
            prior_fact = {key: item for key, item in prior.items() if key not in {"schema_version", "stream", "sequence", "recorded_at"}}
            if prior_fact != value:
                raise ContractError("EVENT_ID_CONFLICT", "Event identity has a different fact", 409)
            return prior
        # Managed reads are audit facts, not resource/search mutations. Preserve
        # their stream sequence but do not spend worker capacity projecting them.
        projection_state = "queued" if projection_required(value) else "done"
        # Definition creation has no prior bindings to reproject. The same
        # transaction's later resource binding emits its own attributes event.
        # Definition updates still require bounded fanout and remain queued.
        cursor.execute("INSERT INTO cf_event_outbox(event_id,stream,schema_version,payload,created_at,audit_state,"
                       "resource_state,resource_next_at,search_state,search_next_at) VALUES(%s,%s,1,'{}',UTC_TIMESTAMP(6),"
                       "'done',%s,UTC_TIMESTAMP(6),%s,UTC_TIMESTAMP(6))", (value["event_id"], stream, projection_state, projection_state))
        value = {**value, "schema_version": 1, "stream": stream, "sequence": str(cursor.lastrowid),
                 "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
        payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        if len(payload.encode()) > 65536:
            raise ContractError("INVALID_REQUEST", "Event exceeds the payload limit", 400)
        cursor.execute("UPDATE cf_event_outbox SET payload=%s WHERE event_id=%s", (payload, value["event_id"]))
        occurred = utc_time(value["occurred_at"]).replace(tzinfo=None)
        cursor.execute("INSERT INTO cf_audit_event(repo_id,object_type,object_id,operation,operator,source,result,occurred_at,"
                       "source_path,target_path,event_id,schema_version,recorded_at,request_id,actor_user_id,actor_kind,delegator,resource_uid,event_payload) "
                       "VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,1,%s,%s,%s,%s,%s,%s,%s)",
                       (value.get("repo_id", ""), value.get("resource_kind", "resource" if value.get("repo_id") else "identity"), value.get("resource_uid", ""), value["action"], value["actor_user_id"], value["source"],
                        value["result"], occurred, value.get("path"), value.get("target_path"), value["event_id"],
                        utc_time(value["recorded_at"]).replace(tzinfo=None), value["request_id"],
                        value["actor_user_id"], value["actor_kind"], value.get("delegator"), value.get("resource_uid"), payload))
        return value

    def resource_hook(self, *, request_id, actor_kind="user", delegator=None):
        identifier(request_id)
        def append(cursor, event):
            fact = {**event, "event_id": str(uuid4()), "occurred_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    "request_id": request_id, "actor_kind": actor_kind, "source": "hub", "result": "succeeded"}
            if delegator is not None:
                fact["delegator"] = delegator
            return self.append(cursor, fact)
        return append


@dataclass(frozen=True)
class EventClaim:
    event_id: str
    consumer: str
    owner: str
    epoch: int
    payload: dict


class Outbox:
    CONSUMERS = frozenset({"resource", "search"})

    def __init__(self, connection):
        if not connection.get_autocommit():
            raise ValueError("outbox requires a dedicated autocommit connection")
        self.connection = connection

    def _require_idle(self):
        # PyMySQL's server_status is the actual last MySQL protocol response;
        # autocommit=True alone does not exclude an explicit BEGIN. Starting a
        # new transaction would implicitly commit a caller's existing work.
        status = getattr(self.connection, "server_status", None)
        if self.connection.get_autocommit():
            if type(status) is int:
                if not status & 1:
                    return
            else:
                # mysqlclient/MySQLdb does not expose the PyMySQL attribute.
                # Same server semantics as EventWriter's transaction probe:
                # outside a transaction SAVEPOINT is a no-op and RELEASE gets
                # ER_SP_DOES_NOT_EXIST(1305). A random name cannot replace a
                # caller's savepoint. No BEGIN/commit/rollback/DDL is issued.
                savepoint = "cf_idle_" + uuid4().hex
                try:
                    with self.connection.cursor() as sql:
                        sql.execute("SAVEPOINT " + savepoint)
                        try:
                            sql.execute("RELEASE SAVEPOINT " + savepoint)
                        except Exception as error:
                            if error.args and type(error.args[0]) is int and error.args[0] == 1305:
                                return
                            raise
                except Exception:
                    pass  # Unknown transport/probe failure is not idle evidence.
        raise ContractError("EVENT_TRANSACTION_CONFLICT", "Dedicated idle event connection required", 503)

    def claim(self, consumer, owner, *, lease_seconds=30):
        if consumer not in self.CONSUMERS or not isinstance(owner, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", owner):
            raise ValueError("invalid outbox consumer or owner")
        if type(lease_seconds) is not int or not 1 <= lease_seconds <= 300:
            raise ValueError("invalid consumer lease")
        self._require_idle()
        self.connection.begin()
        try:
            with self.connection.cursor() as cursor:
                # Search must not enqueue a newer library mutation while an older
                # task is queued/running (including retry backoff). SKIP LOCKED
                # may skip another library, never that stream's predecessor.
                ordered = (" AND NOT EXISTS (SELECT 1 FROM cf_event_outbox prior WHERE prior.stream=next_event.stream"
                    " AND prior.sequence<next_event.sequence AND prior.search_state<>'done')") if consumer == "search" else ""
                cursor.execute("SELECT event_id,payload," + consumer + "_epoch FROM cf_event_outbox next_event WHERE ((" + consumer +
                               "_state='queued' AND " + consumer + "_next_at<=UTC_TIMESTAMP(6)) OR (" + consumer +
                               "_state='running' AND " + consumer + "_expiry<=UTC_TIMESTAMP(6)))" + ordered +
                               " ORDER BY sequence LIMIT 1 FOR UPDATE SKIP LOCKED")
                row = cursor.fetchone()
                if row is None:
                    self.connection.commit()
                    return None
                epoch = row[2] + 1
                cursor.execute("UPDATE cf_event_outbox SET " + consumer + "_state='running'," + consumer + "_owner=%s," +
                               consumer + "_epoch=%s," + consumer + "_expiry=TIMESTAMPADD(SECOND,%s,UTC_TIMESTAMP(6))," +
                               consumer + "_attempts=" + consumer + "_attempts+1 WHERE event_id=%s", (owner, epoch, lease_seconds, row[0]))
                self.connection.commit()
                return EventClaim(row[0], consumer, owner, epoch, json.loads(row[1]))
        except Exception:
            self.connection.rollback()
            raise

    def _update(self, claim, changes, values):
        if claim.consumer not in self.CONSUMERS:
            raise ValueError("unknown outbox consumer")
        name = claim.consumer
        with self.connection.cursor() as cursor:
            cursor.execute("UPDATE cf_event_outbox SET " + changes + " WHERE event_id=%s AND " + name + "_state='running' AND " +
                           name + "_owner=%s AND " + name + "_epoch=%s AND " + name + "_expiry>UTC_TIMESTAMP(6)",
                           (*values, claim.event_id, claim.owner, claim.epoch))
            if cursor.rowcount != 1:
                raise ContractError("WORKER_LEASE_LOST", "Event lease is no longer current", 409)

    def acknowledge(self, claim):
        name = claim.consumer
        if name not in self.CONSUMERS:
            raise ValueError("unknown outbox consumer")
        self._update(claim, name + "_state='done'," + name + "_expiry=NULL," + name + "_error=NULL", ())

    def reconcile_audit_only(self, claim):
        """Explicit one-claim recovery; never reset plans, tasks or whole streams.

        Historical facts can predate disposition fixes. Re-read the exact owned
        lease/fact and reject any frozen search work in ANY generation before
        acknowledging only this consumer. Caller must explicitly invoke this;
        no scheduler, bulk SQL update or automatic search bypass is installed.
        """
        return self._reconcile_audit_only(claim)

    def reconcile_parked_audit_only(self, claim, *, code):
        """Explicit reconciliation of one exact parked audit-only fact.

        Requires its captured claim epoch/payload and observed safe error code.
        Never resumes, deletes or acknowledges resource/index work. No public
        endpoint is registered; trusted operators supply the exact saved claim.
        """
        if not isinstance(code, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", code):
            raise ValueError("exact safe parked error code required")
        return self._reconcile_audit_only(claim, recovery_code=code)

    def _reconcile_audit_only(self, claim, *, recovery_code=None):
        if (not isinstance(claim, EventClaim) or claim.consumer not in self.CONSUMERS or
                type(claim.epoch) is not int or claim.epoch < 1):
            raise ValueError("actual owned event claim required")
        name = claim.consumer
        self._require_idle()
        self.connection.begin()
        try:
            with self.connection.cursor() as sql:
                if recovery_code is None:
                    predicate = name + "_state='running' AND " + name + "_owner=%s AND " + name + "_epoch=%s AND " + name + "_expiry>UTC_TIMESTAMP(6)"
                    parameters = (claim.event_id, claim.owner, claim.epoch)
                else:
                    predicate = name + "_state='recovery' AND " + name + "_owner IS NULL AND " + name + "_expiry IS NULL AND " + name + "_epoch=%s AND " + name + "_error=%s"
                    parameters = (claim.event_id, claim.epoch, recovery_code)
                sql.execute("SELECT payload,stream,sequence,schema_version,audit_state FROM cf_event_outbox WHERE event_id=%s AND " +
                    predicate + " FOR UPDATE", parameters)
                row = sql.fetchone()
                if row is None:
                    raise ContractError("WORKER_LEASE_LOST", "Event lease is no longer current", 409)
                payload = json.loads(row[0])
                if (not isinstance(payload, dict) or payload != claim.payload or type(row[2]) is not int or
                        payload.get("event_id") != claim.event_id or payload.get("schema_version") != 1 or
                        type(payload.get("schema_version")) is not int or row[3] != 1 or row[4] != "done" or
                        sequence(payload.get("sequence")) != row[2] or payload.get("stream") != row[1]):
                    raise ContractError("EVENT_RECOVERY_CONFLICT", "Saved event identity changed", 409)
                fact = normalize_event({key: value for key, value in payload.items()
                    if key not in {"schema_version", "stream", "sequence", "recorded_at"}})
                expected_stream = "repo." + fact["repo_id"] if fact.get("repo_id") else "security"
                if row[1] != expected_stream or projection_required(fact):
                    raise ContractError("EVENT_RECOVERY_REQUIRED", "Event still requires projection", 409)
                # Lock order starts at outbox, as do actual search plan/task
                # writers. No generation is selected to hide older receipts.
                for table in ("cf_search_task", "cf_search_plan", "cf_search_fanout"):
                    sql.execute("SELECT event_id FROM " + table + " WHERE event_id=%s LIMIT 1 FOR UPDATE", (claim.event_id,))
                    if sql.fetchone() is not None:
                        raise ContractError("EVENT_RECOVERY_REQUIRED", "Frozen index work requires separate recovery", 409)
                if recovery_code is None:
                    self._update(claim, name + "_state='done'," + name + "_expiry=NULL," + name + "_error=NULL", ())
                else:
                    sql.execute("UPDATE cf_event_outbox SET " + name + "_state='done'," + name + "_error=NULL WHERE event_id=%s AND " + predicate, parameters)
                    if sql.rowcount != 1:
                        raise ContractError("EVENT_RECOVERY_CONFLICT", "Parked event state changed", 409)
            self.connection.commit()
        finally:
            self.connection.rollback()

    def retry_later(self, claim, *, code, delay_seconds=5):
        if not isinstance(code, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", code):
            raise ValueError("invalid safe event error code")
        if type(delay_seconds) is not int or not 1 <= delay_seconds <= 3600:
            raise ValueError("invalid retry delay")
        name = claim.consumer
        if name not in self.CONSUMERS:
            raise ValueError("unknown outbox consumer")
        self._update(claim, name + "_state='queued'," + name + "_expiry=NULL," + name + "_error=%s," +
                     name + "_next_at=TIMESTAMPADD(SECOND,%s,UTC_TIMESTAMP(6))", (code, delay_seconds))

    def require_recovery(self, claim, *, code):
        """Park one actual owned claim, preserving facts and downstream order.

        No timer/worker restart reclaims this state. A trusted recovery workflow
        must reconcile immutable plans and remote receipts before any resumption;
        this method deliberately provides no generic reset-to-queued operation.
        Existing VARCHAR(16) state columns need no DDL or per-file table.
        """
        if (not isinstance(claim, EventClaim) or claim.consumer not in self.CONSUMERS or
                not isinstance(code, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", code)):
            raise ValueError("actual owned claim and safe recovery code required")
        name = claim.consumer
        self._require_idle()
        self.connection.begin()
        try:
            self._update(claim, name + "_state='recovery'," + name + "_expiry=NULL," +
                name + "_owner=NULL," + name + "_error=%s", (code,))
            self.connection.commit()
        finally:
            self.connection.rollback()
