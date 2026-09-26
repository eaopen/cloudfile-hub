"""Lease operations consumed by actual current CE/C resource authorities."""
import re
import hashlib
from datetime import datetime, timezone
from uuid import UUID, uuid4

from ..common.conditions import compare_revision
from ..common.errors import ContractError, invalid
from ..common.validation import object_fields, identifier, sequence
from ..events.outbox import EventWriter
from ..resources.paths import resource_ref
from ..resources.service import ResourceService
from ..resources.requests import execute
from .store import LockLeaseStore
from .authority import LockManagementAuthority


class FileLockService:
    def __init__(self, resources, *, holder, version_reader, management=None):
        if not isinstance(resources, ResourceService) or not callable(version_reader):
            raise ValueError("actual resource service and protected native version reader required")
        identifier(holder, maximum=128)
        self.resources, self.holder, self.version_reader = resources, holder, version_reader
        self.leases, self.events = LockLeaseStore(), EventWriter()
        if management is not None and (not isinstance(management, LockManagementAuthority) or
                management.state.connection is not resources.store.connection or
                management.actor != resources.write_authority.actor):
            raise ValueError("same-connection current lock management authority required")
        self.management = management

    @staticmethod
    def _reference(value):
        ref = resource_ref(value)
        if ref["kind"] != "file" or len(ref["path"].encode("utf-8")) > 4096:
            raise invalid("File lock requires a bounded file reference")
        return ref

    def _resource(self, sql, ref):
        store = self.resources.store
        evidence = store._validate_evidence(self.resources.reader(sql, ref))
        return evidence, store._row(ref, evidence, locking=True)

    def _audit(self, sql, ref, uid, action, lease):
        # Never include token/digest/holder credentials in the durable fact.
        self.events.append(sql, dict(event_id=str(uuid4()), request_id=self.resources.request_id,
            occurred_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            actor_user_id=self.resources.write_authority.actor, actor_kind="user", source="hub",
            action=action, result="succeeded", repo_id=ref["repo_id"], path=ref["path"],
            resource_uid=uid, resource_kind="file", revision=lease["fencing"]))

    def _retry(self, sql, ref, evidence, *, request, key, operation, mutate):
        # Durable retry identity binds the authenticated holder and digest, not
        # the plaintext token. Replays still run inside current write authority.
        protected = {name: value for name, value in request.items() if name != "token"}
        protected["reference"] = ref
        protected["holder"] = self.holder
        if "token" in request:
            protected["token_digest"] = hashlib.sha256(request["token"].encode("ascii")).hexdigest()
        receipt, _ = execute(sql, provider=self.resources.write_authority.state.provider,
            actor=self.resources.write_authority.actor, operation=operation, key=key,
            request=protected, lifecycle=evidence.lifecycle_ref, secret=self.resources.store.secret,
            mutate=lambda: (mutate(), True))
        row = self.resources.store._row(ref, evidence, locking=True)
        if (row is None or receipt.get("resource_uid") != row["uid"] or receipt.get("resource") != ref):
            raise ContractError("LOCK_CONFLICT", "Saved lease receipt does not match current resource", 409)
        # A saved success can outlive its lease. Return a current locked status
        # separately instead of promoting the old receipt into a write grant.
        current = self.leases.status(sql, resource_uid=receipt["resource_uid"], repo_id=ref["repo_id"])
        return dict(receipt=receipt, current_lease=current)

    def acquire(self, request, *, idempotency_key):
        object_fields(request, ("reference", "revision", "base_version", "token"), ("seconds",))
        ref = self._reference(request["reference"])
        seconds = request.get("seconds", 600)
        actor = self.resources.write_authority.actor
        self.leases._holder(actor, self.holder, request["token"], seconds)
        if not isinstance(request["base_version"], str) or not re.fullmatch(r"[0-9a-f]{40}", request["base_version"]):
            raise invalid("Expected native content version required")
        def mutate(sql, reference, evidence, row):
            store = self.resources.store
            compare_revision(request["revision"], store._snapshot(reference, evidence, row)["revision"])
            # Must read the actual current native file under the SAME authority
            # and lifecycle scope, not an earlier RPC, hash-as-UID or repo head.
            current = self.version_reader(sql, reference, evidence)
            if current != request["base_version"]:
                raise ContractError("RESOURCE_VERSION_CONFLICT", "File content changed", 409)
            if row is None:
                uid = str(uuid4())
                sql.execute("INSERT INTO cf_resource(uid,repo_id,kind,path,path_hash,lifecycle_ref,revision,description,local_open_type,state,updated_at) VALUES(%s,%s,'file',%s,%s,%s,1,NULL,NULL,'active',UTC_TIMESTAMP(6))", (uid, reference["repo_id"], reference["path"], store._hash(reference["path"]), evidence.lifecycle_ref))
                # UID creation changes sparse search metadata. Its own event is
                # separate from the lease's audit-only transition.
                store.mutation_hook(sql, dict(action="resource.attributes.updated", actor_user_id=actor,
                    resource_uid=uid, repo_id=reference["repo_id"], path=reference["path"], revision="1"))
                row = store._row(reference, evidence, locking=True)
            lease = self.leases.acquire(sql, resource_uid=row["uid"], repo_id=reference["repo_id"],
                actor=actor, holder=self.holder, token=request["token"], base_version=current, seconds=seconds)
            self._audit(sql, reference, row["uid"], "lock.acquired", lease)
            return dict(resource_uid=row["uid"], resource=reference,
                resource_revision=store._snapshot(reference, evidence, row)["revision"], **lease)
        def apply(sql, reference):
            evidence, row = self._resource(sql, reference)
            return self._retry(sql, reference, evidence, request=request, key=idempotency_key,
                operation="locks.acquire", mutate=lambda: mutate(sql, reference, evidence, row))
        return self.resources.write_authority.consume(ref, apply)

    def change(self, request, *, idempotency_key, release=False):
        object_fields(request, ("reference", "resource_uid", "fencing", "token"), ("seconds",))
        ref = self._reference(request["reference"])
        try:
            if str(UUID(request["resource_uid"])) != request["resource_uid"]:
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            raise invalid("Canonical resource UID required") from None
        fence = sequence(request["fencing"])
        if not 1 <= fence <= 2 ** 64 - 1 or type(release) is not bool:
            raise invalid("Valid lease fencing required")
        actor = self.resources.write_authority.actor
        seconds = request.get("seconds", 600)
        self.leases._holder(actor, self.holder, request["token"], seconds)
        def apply(sql, reference):
            evidence, row = self._resource(sql, reference)
            if row is None or row["uid"] != request["resource_uid"]:
                raise ContractError("LOCK_CONFLICT", "Resource lifecycle changed", 409)
            return self._retry(sql, reference, evidence, request=request, key=idempotency_key,
                operation="locks.release" if release else "locks.renew",
                mutate=lambda: mutate(sql, reference, row))
        def mutate(sql, reference, row):
            lease = self.leases.change(sql, resource_uid=row["uid"], repo_id=reference["repo_id"], actor=actor,
                holder=self.holder, token=request["token"], fencing=fence, release=release, seconds=seconds)
            self._audit(sql, reference, row["uid"], "lock.released" if release else "lock.renewed", lease)
            return dict(resource_uid=row["uid"], resource=reference, **lease)
        return self.resources.write_authority.consume(ref, apply)

    def status(self, request):
        object_fields(request, ("reference",))
        ref = self._reference(request["reference"])
        def read(sql, reference):
            _, row = self._resource(sql, reference)
            if row is None:
                return dict(resource_uid=None, active=False, fencing="0", owner_user_id=None,
                    holder_id=None, base_version=None, expires_at=None)
            return dict(resource_uid=row["uid"], **self.leases.status(sql, resource_uid=row["uid"], repo_id=reference["repo_id"]))
        return self.resources.read_authority.consume(ref, read)

    def force_release(self, request, *, idempotency_key):
        object_fields(request, ("reference", "resource_uid", "fencing", "reason"))
        ref = self._reference(request["reference"])
        reason = request["reason"]
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 512 or any(ord(c) < 32 for c in reason):
            raise invalid("Management release requires a bounded reason")
        fence = sequence(request["fencing"])
        if not 1 <= fence < 2 ** 64 - 1:
            raise invalid("Bounded management fencing required")
        if self.management is None:
            raise ContractError("LOCK_UNAVAILABLE", "Lock management authority is unavailable", 503)
        def apply(sql, reference):
            evidence, row = self._resource(sql, reference)
            if row is None or row["uid"] != request["resource_uid"]:
                raise ContractError("LOCK_CONFLICT", "Resource lifecycle changed", 409)
            def mutate():
                lease = self.leases.force_release(sql, resource_uid=row["uid"], repo_id=reference["repo_id"], fencing=fence)
                self.events.append(sql, dict(event_id=str(uuid4()), request_id=self.resources.request_id,
                    occurred_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    actor_user_id=self.management.actor, actor_kind="user", source="hub", action="lock.force-released",
                    result="succeeded", repo_id=reference["repo_id"], path=reference["path"], resource_uid=row["uid"],
                    resource_kind="file", revision=lease["fencing"], reason=reason))
                return dict(resource_uid=row["uid"], resource=reference, **lease)
            return self._retry(sql, reference, evidence, request=request, key=idempotency_key,
                operation="locks.force-release", mutate=mutate)
        return self.management.consume(ref, apply)
