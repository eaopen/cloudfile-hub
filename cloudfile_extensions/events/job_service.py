"""Audit job transitions joined to the actual authorization transaction.

Private adapter: never starts, commits or rolls back its caller's transaction.
Do not use the ordinary JobStore transaction methods inside a policy consumer.
"""
from contextlib import contextmanager

from ..jobs.store import JobStore


class AuditTransactionJobs(JobStore):
    def __init__(self, connection, cursor):
        super().__init__(connection)
        self.cursor = cursor

    @contextmanager
    def _transaction(self):
        # SAVEPOINT cannot succeed without an actual transaction in the native
        # MySQL contract used by EventWriter. Effects use the same connection;
        # the authority's final epoch check owns commit/rollback.
        self.cursor.execute("SAVEPOINT cf_audit_job_scope")
        self.cursor.execute("ROLLBACK TO SAVEPOINT cf_audit_job_scope")
        self.cursor.execute("RELEASE SAVEPOINT cf_audit_job_scope")
        yield
