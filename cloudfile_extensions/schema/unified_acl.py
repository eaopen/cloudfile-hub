"""Verify the immutable 040 migration against its 042 successor.

Independent directory sharing was never enabled; no data conversion exists.
"""


def successor_steps():
    from .runner import load_migrations
    return next(m.steps for m in load_migrations() if m.version == '042_unified_directory_acl')
