# -*- coding: utf-8 -*-
"""Pure authority-state rules shared by Hub callers and contract tests.

Only a genuinely unsupported stock server or an explicitly disabled feature
may use native CE pass-through.  Once the directory-ACL authority is active,
missing, malformed or stale answers are denials at the final content boundary.
"""

from collections import namedtuple


AuthorityVerdict = namedtuple('AuthorityVerdict', 'denied restricted_path')

_PASSTHROUGH = frozenset(('unsupported-stock', 'inactive-disabled'))


def classify(authority):
    """Return ``passthrough``, ``rules`` or ``deny`` for one wire response."""
    if not isinstance(authority, dict):
        return 'deny'

    state = authority.get('name', authority.get('state'))
    enabled = authority.get('feature_enabled')
    supported = authority.get('feature_supported')
    rpc_status = authority.get('rpc_status')

    if state == 'unsupported-stock':
        return 'passthrough' if supported is False and enabled is False else 'deny'
    if state == 'inactive-disabled':
        return 'passthrough' if supported is True and enabled is False else 'deny'
    if state != 'active-valid':
        return 'deny'
    if supported is not True or enabled is not True or rpc_status != 'ok':
        return 'deny'

    issued = authority.get('issued_revision', authority.get('revision'))
    current = authority.get('current_revision', authority.get('revision'))
    if not isinstance(issued, int) or issued < 1 or issued != current:
        return 'deny'
    return 'rules'


def next_revision(current, operation, force_target=None):
    """Produce a strictly increasing revision for every authoritative write."""
    if operation not in ('bootstrap', 'create-rule', 'update-rule',
                         'delete-rule', 'clear-rules'):
        raise ValueError('unknown ACL revision operation: %s' % operation)
    base = 0 if current is None else int(current)
    if base < 0:
        raise ValueError('ACL revision cannot be negative')
    candidate = base + 1
    if force_target is not None:
        candidate = max(candidate, int(force_target) + 1)
    return candidate


def recheck_at_boundary(issued_revision, current_revision,
                        cached_restricted_path=''):
    """Reject a cached decision unless its authority revision is still live."""
    if (not isinstance(issued_revision, int) or issued_revision < 1 or
            not isinstance(current_revision, int) or
            issued_revision != current_revision):
        return AuthorityVerdict(True, '')
    return AuthorityVerdict(False, cached_restricted_path or '')
