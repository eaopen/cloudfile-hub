"""Bounded content-id lookup for diagnostics, never a favorite identity source.

Content ids can be shared by different resources. A unique search hit is only
an auxiliary hint and must not rebind a relationship without an operation map.
"""
from dataclasses import dataclass
import posixpath
import stat
import time


@dataclass(frozen=True)
class LookupResult:
    status: str
    path: str | None = None


class LookupBudget:
    """Share node/RPC/time limits across lookups, including wide empty trees.

    The deadline is checked around RPCs; the transport must also bound each RPC
    because a synchronous call cannot be interrupted by this pure helper.
    """

    def __init__(self, max_entries=2000, max_calls=64, max_seconds=0.25,
                 clock=time.monotonic):
        self.entries = max_entries
        self.calls = max_calls
        self.clock = clock
        self.deadline = clock() + max_seconds

    def exhausted(self):
        return self.entries <= 0 or self.calls <= 0 or self.clock() >= self.deadline


def lookup_content_hint(list_entries, repo_id, obj_id, root='/', max_depth=512,
                        budget=None):
    """Inspect a bounded tree and report ambiguity/failure instead of a guess."""
    budget = budget or LookupBudget()
    pending = [(root, 0)]
    match = None
    while pending:
        if budget.exhausted():
            return LookupResult('budget_exhausted')
        path, depth = pending.pop()
        if depth >= max_depth:
            return LookupResult('budget_exhausted')
        budget.calls -= 1
        try:
            entries = list_entries(repo_id, path) or ()
            for entry in entries:
                if budget.entries <= 0 or budget.clock() >= budget.deadline:
                    return LookupResult('budget_exhausted')
                budget.entries -= 1
                target = posixpath.join(path, entry.obj_name)
                if entry.obj_id == obj_id:
                    if match is not None and target != match:
                        return LookupResult('ambiguous')
                    match = target
                if stat.S_ISDIR(entry.mode):
                    pending.append((target, depth + 1))
            if budget.clock() >= budget.deadline:
                return LookupResult('budget_exhausted')
        except Exception:
            return LookupResult('unavailable')
    return LookupResult('unique', match) if match else LookupResult('not_found')
