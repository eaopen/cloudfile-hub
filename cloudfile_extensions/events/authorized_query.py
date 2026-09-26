"""Actual same-transaction CE/C audit page consumer; no HTTP/export enablement."""
from ..authorization.read import ContentReadAuthority, LibraryWideManagementAuthority
from ..common.errors import ContractError
from ..resources.paths import resource_ref
from ..resources.store import ResourceStore
from ..tags.definitions import uuid_value
from .query import AuditReader
from .service import AuditService
from .privacy import redact_event
from .job_service import AuditTransactionJobs
from ..jobs.store import JobStore
from uuid import UUID


class AuthorizedAuditQuery:
    def __init__(self, preparation, core, *, cloud_mode, request_id, secret, redact):
        self.authority = ContentReadAuthority(preparation, core,
            cloud_mode=cloud_mode, request_id=request_id)
        self.management = LibraryWideManagementAuthority(preparation, core,
            cloud_mode=cloud_mode, request_id=request_id)
        self.managed = False
        self.cursor = None
        self.repo_id = None
        self.epoch = None
        reader = AuditReader(preparation.state.connection, secret=secret, authorize=self._authorize)
        def no_export(*args, **kwargs):
            raise ContractError("AUDIT_UNAVAILABLE", "Audit export runtime is unavailable", 503)
        self.service = AuditService(reader, None, export_guard=no_export, redact=redact)

    def create_export(self, request, *, idempotency_key):
        filters = AuditService._filters(request)
        repo = filters.pop("repo_id")
        def submit():
            jobs = AuditTransactionJobs(self.authority.state.connection, self.cursor)
            job_id, created = jobs.submit(actor=self.authority.actor, actor_kind="user",
                kind="audit.export", scope=dict(type="repo", provider="cloudfile", external_id=repo),
                request=filters, idempotency_key=idempotency_key)
            return AuditService._dto(jobs.get(job_id)), created
        return self._consume(repo, submit, export=True)

    def _owned_export(self, job_id):
        try:
            job_id = str(UUID(job_id))
        except (ValueError, TypeError, AttributeError):
            raise ContractError("INVALID_REQUEST", "Invalid audit export identity", 400) from None
        job = JobStore(self.authority.state.connection).get(job_id)
        if (job["kind"] != "audit.export" or job["actor_kind"] != "user"
                or job["actor"] != self.authority.actor or job["barrier_active"]
                or job["scope"].get("type") != "repo"
                or job["scope"].get("provider") != "cloudfile"):
            raise ContractError("NOT_FOUND", "Audit export is not available", 404)
        resource_ref(dict(repo_id=job["scope"]["external_id"], path="/", kind="dir"))
        return job

    def export_status(self, job_id):
        job = self._owned_export(job_id)
        def read():
            current = self._owned_export(job["job_id"])
            if current["scope"] != job["scope"]:
                raise ContractError("AUDIT_UNAVAILABLE", "Audit export scope changed", 503)
            return AuditService._dto(current)
        return self._consume(job["scope"]["external_id"], read, export=True)

    def cancel_export(self, job_id):
        job = self._owned_export(job_id)
        def cancel():
            current = self._owned_export(job["job_id"])
            if current["scope"] != job["scope"]:
                raise ContractError("AUDIT_UNAVAILABLE", "Audit export scope changed", 503)
            jobs = AuditTransactionJobs(self.authority.state.connection, self.cursor)
            return AuditService._dto(jobs.cancel(current["job_id"],
                actor=self.authority.actor, actor_kind="user"))
        return self._consume(job["scope"]["external_id"], cancel, export=True)

    def _authorize(self, actor, event):
        if self.cursor is None or actor != self.authority.actor or event.get("repo_id") != self.repo_id:
            return False
        if set(event) == {"repo_id"}:
            return True  # root CE/C read already held in the actual transaction
        paths = [event.get(name) for name in ("source_path", "target_path") if event.get(name) is not None]
        if not paths:
            # Library/security facts require a separate audit-management scope.
            return self.managed
        kind = event.get("_object_type")
        if kind not in {"file", "dir"}:
            uid = event.get("resource_uid")
            if uid is None:
                return False  # never infer a historical kind from a filename
            uuid_value(uid)
            ResourceStore._storage(self.cursor)
            self.cursor.execute("SELECT repo_id,kind FROM cf_resource WHERE uid=%s FOR UPDATE", (uid,))
            rows = self.cursor.fetchall()
            if len(rows) != 1 or rows[0][0] != self.repo_id or rows[0][1] not in {"file", "dir"}:
                return False
            kind = rows[0][1]
        for path in set(paths):
            ref = resource_ref(dict(repo_id=self.repo_id, path=path, kind=kind))
            allowed = self.authority.authorize(self.cursor, actor, ref)
            if self.authority.epoch != self.epoch:
                raise ContractError("SUBJECT_UNAVAILABLE", "Audit subject changed during the page", 503)
            if allowed is not True:
                return False
        return True

    def events(self, filters, *, limit=100, cursor=None):
        filters = AuditService._filters(filters)
        return self._consume(filters["repo_id"], lambda: self.service.events(
            actor=self.authority.actor, filters=filters, limit=limit, cursor=cursor))

    def export_page(self, filters, *, limit=200, cursor=None, upper_bound=None):
        """Internal export page; the cutoff is never accepted by query HTTP."""
        filters = AuditService._filters(filters)
        if type(upper_bound) is not int or not 0 <= upper_bound <= 2 ** 63 - 1:
            raise ContractError("INVALID_REQUEST", "Invalid audit export cutoff", 400)
        def page():
            value = self.service.reader.list(actor=self.authority.actor, **filters,
                limit=limit, cursor=cursor, upper_bound=upper_bound)
            return {"items": [redact_event(self.service.redact, self.authority.actor, event)
                    for event in value["items"]], "next_cursor": value["next_cursor"]}
        return self._consume(filters["repo_id"], page, export=True)

    def export_upper_bound(self, repo_id):
        root = resource_ref(dict(repo_id=repo_id, path="/", kind="dir"))
        return self._consume(root["repo_id"], self.service.reader.upper_bound, export=True)

    def authorize_export(self, actor, repo_id):
        if actor != self.authority.actor:
            return False
        root = resource_ref(dict(repo_id=repo_id, path="/", kind="dir"))
        return self._consume(root["repo_id"], lambda: True, export=True)

    def _consume(self, repo_id, operation, *, export=False):
        root = dict(repo_id=repo_id, path="/", kind="dir")
        def read(sql, ref):
            self.cursor, self.repo_id, self.epoch = sql, ref["repo_id"], self.authority.epoch
            try:
                self.managed = self.management.authorize(sql, self.authority.actor, ref) is True
                if self.management.epoch != self.epoch:
                    raise ContractError("SUBJECT_UNAVAILABLE", "Audit management subject changed", 503)
                if export and not self.managed:
                    raise ContractError("ACCESS_DENIED", "Whole-library audit export is not allowed", 403)
                return operation()
            finally:
                self.cursor = self.repo_id = self.epoch = None
                self.managed = False
                self.management.epoch = self.management.current_subject = self.management.effective_access = None
                self.management.is_owner = False
        return self.authority.consume(root, read)
