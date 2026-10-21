"""Explicit fixed single-user refresh worker, without management API enablement."""
from contextlib import ExitStack
from uuid import uuid4

from ..authorization.resources import PolicyResources
from ..jobs.runtime import run_loop
from ..jobs.store import JobStore
from ..jobs.worker import Handler, JobWorker
from .refresh_worker import UserRefreshJob


class UserRefreshBackground:
    def __init__(self, resources, *, owner, lease_seconds=30):
        if not isinstance(resources, PolicyResources):
            raise ValueError("actual configured policy resources required")
        self.stack = ExitStack()
        self.closed = self.running = False
        try:
            self.connection = self.stack.enter_context(resources.connection())
            def preparation(user, execution):
                if execution.store.connection is not self.connection:
                    raise ValueError("refresh execution must use this worker connection")
                return resources.preparation_on_connection(self.connection, user, str(uuid4()))
            handler = UserRefreshJob(preparation_factory=preparation, provider=resources.provider)
            self.worker = JobWorker(JobStore(self.connection), owner=owner,
                handlers={UserRefreshJob.KIND: Handler(handler)}, lease_seconds=lease_seconds)
        except Exception:
            self.close()
            raise

    def run_once(self):
        if self.closed or self.running:
            raise RuntimeError("refresh background is closed or already running")
        self.running = True
        try:
            return self.worker.run_once()
        except Exception:
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
            raise RuntimeError("finish active refresh before shutdown")
        if not self.closed:
            self.closed = True
            self.stack.close()

    def __enter__(self):
        if self.closed:
            raise RuntimeError("refresh background is closed")
        return self

    def __exit__(self, *args):
        self.close()
