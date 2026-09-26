"""CSV consumer of real, current, same-transaction audit export pages.

An owned AuthorizedAuditQuery must remain alive throughout generation. This
does not register a worker, publish a file, or authorize later HTTP delivery.
"""
from ..common.errors import ContractError
from ..resources.paths import resource_ref
from .authorized_query import AuthorizedAuditQuery
from .export import AuditCSV


class _ExportPages:
    def __init__(self, query, repo_id):
        self.query, self.repo_id = query, repo_id

    def upper_bound(self):
        return self.query.export_upper_bound(self.repo_id)

    def list(self, *, actor, repo_id, upper_bound, limit, cursor, **filters):
        if actor != self.query.authority.actor or repo_id != self.repo_id:
            raise ContractError("ACCESS_DENIED", "Audit export identity is inconsistent", 403)
        return self.query.export_page(dict(repo_id=repo_id, **filters),
            upper_bound=upper_bound, limit=limit, cursor=cursor)


class AuthorizedAuditCSV(AuditCSV):
    def __init__(self, query, *, repo_id, max_rows=10000,
                 max_bytes=10 * 1024 * 1024, max_pages=100):
        if not isinstance(query, AuthorizedAuditQuery):
            raise ValueError("owned actual audit query required")
        self.query = query
        self.repo_id = resource_ref(dict(repo_id=repo_id, path="/", kind="dir"))["repo_id"]
        # Pages are already deployment-redacted inside their authorization
        # transaction. Do not invoke a stateful redactor again outside it.
        super().__init__(_ExportPages(query, self.repo_id),
            authorize_export=self._authorize, redact=lambda actor, event: event,
            max_rows=max_rows, max_bytes=max_bytes, max_pages=max_pages)

    def _authorize(self, actor, repo_id):
        if repo_id != self.repo_id:
            return False
        return self.query.authorize_export(actor, repo_id)
