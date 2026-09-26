"""Actual same-transaction CE/C audit page consumer; no HTTP/export enablement."""
from ..authorization.read import ContentReadAuthority, LibraryWideManagementAuthority
from ..common.errors import ContractError
from ..resources.paths import resource_ref
from ..resources.store import ResourceStore
from ..tags.definitions import uuid_value
from .query import AuditReader
from .service import AuditService


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
        root = dict(repo_id=filters["repo_id"], path="/", kind="dir")
        def read(sql, ref):
            self.cursor, self.repo_id, self.epoch = sql, ref["repo_id"], self.authority.epoch
            try:
                self.managed = self.management.authorize(sql, self.authority.actor, ref) is True
                if self.management.epoch != self.epoch:
                    raise ContractError("SUBJECT_UNAVAILABLE", "Audit management subject changed", 503)
                return self.service.events(actor=self.authority.actor, filters=filters,
                    limit=limit, cursor=cursor)
            finally:
                self.cursor = self.repo_id = self.epoch = None
                self.managed = False
                self.management.epoch = self.management.current_subject = self.management.effective_access = None
                self.management.is_owner = False
        return self.authority.consume(root, read)
