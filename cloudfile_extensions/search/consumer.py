"""One-shot ordered search consumer. Deployment/loop registration is external."""
import re

from ..common.errors import ContractError
from ..events.outbox import Outbox
from .event_execution import SearchEventExecution
from .projection import AttributeSearchProjection
from .fanout_coordinator import TagFanoutCoordinator
from .global_fanout_coordinator import GlobalTagFanoutCoordinator


class SearchEventConsumer:
    def __init__(self, outbox, execution, projection, *, owner, generation, fanout=None, global_fanout=None):
        if (not isinstance(outbox, Outbox) or not isinstance(execution, SearchEventExecution) or
                not isinstance(projection, AttributeSearchProjection) or
                outbox.connection is not execution.store.connection or
                not isinstance(owner, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", owner) or
                not isinstance(generation, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", generation)):
            raise ValueError("owned ordered consumer and pinned index generation required")
        self.outbox, self.execution, self.projection = outbox, execution, projection
        self.owner, self.generation = owner, generation
        if fanout is not None and (not isinstance(fanout, TagFanoutCoordinator) or
                fanout.execution.store.connection is not outbox.connection or
                fanout.execution.client.index != execution.client.index):
            raise ValueError("fanout must share owned persistence and pinned index")
        self.fanout = fanout
        if global_fanout is not None and (not isinstance(global_fanout, GlobalTagFanoutCoordinator) or
                global_fanout.execution.store.connection is not outbox.connection or
                global_fanout.execution.client.index != execution.client.index):
            raise ValueError("global fanout must share owned persistence and pinned index")
        self.global_fanout = global_fanout

    def run_once(self):
        claim = self.outbox.claim("search", self.owner, lease_seconds=60)
        if claim is None:
            return "idle"
        try:
            if (claim.payload.get("action") == "tags.definition.updated" and claim.payload.get("repo_id") is None and
                    self.global_fanout is not None):
                if self.global_fanout.advance(claim, generation=self.generation):
                    return "completed"
                self.outbox.retry_later(claim, code="INDEX_TASK_PENDING", delay_seconds=2)
                return "pending"
            if claim.payload.get("action") == "tags.definition.updated" and self.fanout is not None:
                if self.fanout.advance(claim, generation=self.generation):
                    return "completed"
                self.outbox.retry_later(claim, code="INDEX_TASK_PENDING", delay_seconds=2)
                return "pending"
            plan = self.execution.store.load(claim, generation=self.generation)
            if plan is None:
                steps = self.projection.plan(claim)
                self.execution.store.freeze(claim, generation=self.generation,
                    index=self.execution.client.index, steps=steps)
            complete = self.execution.advance(claim, generation=self.generation)
            if complete:
                # Execution already acknowledged the exact successful plan in SQL.
                return "completed"
            self.outbox.retry_later(claim, code="INDEX_TASK_PENDING", delay_seconds=2)
            return "pending"
        except ContractError as error:
            if error.code == "WORKER_LEASE_LOST":
                raise
            code = error.code if re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", error.code) else "INDEX_UNAVAILABLE"
            # Durable submitting remains unknown; re-claim only checks it, never
            # resets it or re-dispatches. Same-stream successor stays blocked.
            self.outbox.retry_later(claim, code=code, delay_seconds=30)
            return "recovery_required" if code in {"SEARCH_SUBMISSION_UNKNOWN", "SEARCH_TASK_FAILED", "SEARCH_PLAN_CONFLICT", "SEARCH_PROJECTION_PENDING"} else "retry"
        except Exception:
            # An uncertain network/SQL failure may already have persisted intent.
            # Preserve it and never acknowledge or reset the task here.
            self.outbox.retry_later(claim, code="INDEX_UNAVAILABLE", delay_seconds=30)
            return "retry"
