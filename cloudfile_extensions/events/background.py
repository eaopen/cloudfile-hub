"""Explicit single-thread audit worker/retention lifecycle, never auto-started.

Trusted host supplies its assembled audit factory and DB settings. Two dedicated
SQL connections separate lease effects from cleanup; subject scopes own further
connections. A failed connection is closed, never transparently reconnected.
"""
from ..jobs.runtime import connect_database, run_loop
from ..jobs.store import JobStore
from ..jobs.worker import Handler, JobWorker
from ..schema.runner import SchemaRunner
from .retention import AuditExportRetention
from .runtime import AuditQueryFactory


class AuditBackground:
    def __init__(self, factory, *, environment, owner, lease_seconds=30, cleanup_limit=100):
        if (not isinstance(factory, AuditQueryFactory) or factory.result_root is None
                or type(cleanup_limit) is not int or not 1 <= cleanup_limit <= 1000):
            raise ValueError("configured audit factory and bounded cleanup required")
        self.job_connection = self.cleanup_connection = None
        self.retention = None
        self.running = self.closed = False
        self.cleanup_limit = cleanup_limit
        self.last_cleanup = None
        try:
            self.job_connection = connect_database(environment)
            self.cleanup_connection = connect_database(environment)
            if self.job_connection is self.cleanup_connection:
                raise ValueError("dedicated audit background connections required")
            for connection in (self.job_connection, self.cleanup_connection):
                SchemaRunner(connection).require_current()
            self.worker = JobWorker(JobStore(self.job_connection), owner=owner,
                handlers={"audit.export": Handler(factory.export_handler(result_root=factory.result_root))},
                lease_seconds=lease_seconds)
            self.retention = AuditExportRetention(JobStore(self.cleanup_connection),
                result_root=factory.result_root)
        except Exception:
            self.close()
            raise

    def run_once(self):
        if self.closed or self.running:
            raise RuntimeError("audit background is closed or already running")
        self.running = True
        try:
            job_id = self.worker.run_once()
            self.last_cleanup = self.retention.run_once(limit=self.cleanup_limit)
            return job_id
        except Exception:
            # Terminal runtime failure: supervisor must construct a new runtime.
            # Do not reconnect and silently continue with uncertain lock state.
            self.running = False
            self.close()
            raise
        finally:
            self.running = False

    def run(self, stop, *, poll_seconds=2, once=False, emit=lambda value: None):
        try:
            return run_loop(self, stop, poll_seconds=poll_seconds, once=once, emit=emit)
        finally:
            self.close()

    def close(self):
        if self.running:
            raise RuntimeError("finish active audit work before shutdown")
        if self.closed:
            return
        self.closed = True
        try:
            if self.retention is not None:
                self.retention.close()
        finally:
            for connection in (self.cleanup_connection, self.job_connection):
                if connection is not None:
                    try:
                        connection.close()
                    except Exception:
                        pass

    def __enter__(self):
        if self.closed:
            raise RuntimeError("audit background is closed")
        return self

    def __exit__(self, *args):
        self.close()
