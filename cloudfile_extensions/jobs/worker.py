"""Bounded trusted job dispatch; domain effects must obey the claim's fencing.

No shell commands or request-selected handlers are loaded. A deployment worker
owns its connection; this dispatcher does not share it with background threads.
"""

from dataclasses import dataclass
import re
import time

from ..common.errors import ContractError


@dataclass(frozen=True)
class Handler:
    execute: object
    barrier_guard: object = None

    def __post_init__(self):
        if not callable(self.execute) or (self.barrier_guard is not None and not callable(self.barrier_guard)):
            raise ValueError("invalid trusted job handler")


@dataclass(frozen=True)
class JobResult:
    result_ref: str = None


class Execution:
    def __init__(self, store, claim, lease_seconds, notify=lambda **values: None):
        self.store = store
        self.claim = claim
        self.lease_seconds = lease_seconds
        self.notify = notify

    def checkpoint(self, *, step, value):
        # The same epoch is checked on every heartbeat/checkpoint. Domain handlers
        # must additionally check it through their authoritative commit guard.
        self.store.checkpoint(self.claim, step=step, checkpoint=value, lease_seconds=self.lease_seconds)
        self.notify(state="job_checkpoint", step=step)


class JobWorker:
    def __init__(self, store, *, owner, handlers, lease_seconds=30, observe=lambda value: None):
        if (not isinstance(handlers, dict) or not 1 <= len(handlers) <= 16
                or any(not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9._-]{0,63}", name)
                       or not isinstance(handler, Handler) for name, handler in handlers.items())
                or not isinstance(owner, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", owner)
                or type(lease_seconds) is not int or not 1 <= lease_seconds <= 300):
            raise ValueError("invalid worker configuration")
        if not callable(observe):
            raise ValueError("invalid worker observer")
        self.observe = observe
        self.store = store
        self.owner = owner
        self.handlers = dict(handlers)
        self.lease_seconds = lease_seconds

    def run_once(self):
        claim = self.store.claim(self.owner, kinds=tuple(sorted(self.handlers)), lease_seconds=self.lease_seconds)
        if claim is None:
            return None
        handler = self.handlers[claim.kind]
        started = time.monotonic()
        def notify(**values):
            # Operational logs are not audit facts or commit acknowledgements.
            # A broken log sink must never change a persisted job outcome.
            try:
                self.observe(dict(job_id=claim.job_id, operation=claim.kind,
                                  lease_epoch=str(claim.epoch),
                                  elapsed_ms=int((time.monotonic() - started) * 1000), **values))
            except Exception:
                pass
        notify(state="job_started")
        try:
            current = self.store.get(claim.job_id)
            if current["barrier_active"] and handler.barrier_guard is None:
                # Reject before executing side effects, not only at completion.
                raise ContractError("BARRIER_RECONCILIATION_REQUIRED", "Trusted reconciliation is required", 409)
            execution = Execution(self.store, claim, self.lease_seconds, notify)
            execution.checkpoint(step="processing", value=current["checkpoint"] or {})
            result = handler.execute(execution)
            if not isinstance(result, JobResult):
                raise ValueError("handler must return a bounded job result")
            self.store.complete(claim, result_ref=result.result_ref, barrier_guard=handler.barrier_guard)
            notify(state="job_succeeded")
        except Exception as error:
            code = error.code if isinstance(error, ContractError) else "JOB_HANDLER_FAILED"
            if not isinstance(code, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", code):
                code = "JOB_HANDLER_FAILED"
            try:
                self.store.fail(claim, code=code)
                notify(state="job_failed", error_code=code)
            except ContractError as lost:
                if lost.code != "WORKER_LEASE_LOST":
                    raise
                notify(state="job_lease_lost", error_code="WORKER_LEASE_LOST")
                # Cancelled/expired/reassigned work must not overwrite its successor.
            # Never persist exception messages, request bodies or credentials.
        return claim.job_id
