# -*- coding: utf-8 -*-
"""Turn a desired share state into a list of share operations.

Decision source: eap-cloudfile docs/review/cloudfile_decision_20260827.md §4.4.

Pure data in, pure data out -- same split as cloudfile_ext.sso.reconcile, for
the same reason: the rules below are where somebody loses access if they are
wrong, so they have to be testable without a running server.

The rules, in the order the decision states them
------------------------------------------------

1.  An external id that does not resolve to a mapped group is an ERROR, never
    a guess. Matching by display name could hand a library to whichever group
    happens to share the name; the decision forbids it outright.
2.  A missing share is added; a drifted permission is updated in place.
3.  A desired entry removed (or disabled on the etech side) revokes **only**
    shares this ledger records as applied by this integration. A share that
    exists in Seafile without a ledger row was made by a person or another
    system, and is not ours to take back.
4.  Nothing here runs on a login path or inside a permission check. The output
    is a plan for a background task; applying it is elsewhere
    (cloudfile_ext.sso.library_share_service).
"""

from collections import namedtuple

DesiredShare = namedtuple('DesiredShare', 'external_group_id permission')

SharePlan = namedtuple('SharePlan', 'add update revoke errors')


def build(desired, ledger, resolved):
    """Compute the plan that makes applied shares match ``desired``.

    ``desired``   iterable of DesiredShare(external_group_id, 'r'|'rw') --
                  the external system's complete desired state for one repo.
                  An empty iterable is a fact ("share this with nobody") and
                  is honoured; the caller distinguishes it from a failed read
                  before getting here.
    ``ledger``    ``{external_group_id: {'seafile_group_id', 'permission',
                  'state', 'last_error'}}`` -- cf_managed_library_share rows.
    ``resolved``  ``{external_group_id: seafile_group_id}`` -- live readings
                  from cf_sso_group_map. Ids not in here are unmapped.

    Returns SharePlan(add=[(gid, ext, perm)], update=[(gid, ext, perm)],
    revoke=[(gid, ext)], errors=[(ext, reason)]).
    """
    add, update, revoke, errors = [], [], [], []

    desired_by_id = {}
    duplicates = set()
    for entry in desired:
        permission = (entry.permission or '').strip()
        if permission not in ('r', 'rw'):
            errors.append((entry.external_group_id,
                           'invalid permission %r' % entry.permission))
            continue
        if entry.external_group_id in desired_by_id:
            # A duplicate desired entry is a contract error upstream; applying
            # either half would silently pick a winner, so *both* halves are
            # rejected -- the entry drops out of the desired state entirely
            # and whatever share exists stays as it was.
            duplicates.add(entry.external_group_id)
            continue
        desired_by_id[entry.external_group_id] = permission

    for external_id in duplicates:
        errors.append((external_id, 'duplicated in desired'))
        desired_by_id.pop(external_id, None)

    for external_id, permission in sorted(desired_by_id.items()):
        group_id = resolved.get(external_id)
        if group_id is None:
            # Rule 1: unresolved ids never guess. The row goes to errors so
            # the caller can mark it and alert, and the share -- if any --
            # stays exactly as it was.
            errors.append((external_id, 'external id not mapped to a group'))
            continue

        row = ledger.get(external_id)
        if row is None or row.get('state') == 'REVOKED':
            add.append((group_id, external_id, permission))
        elif row.get('permission') != permission:
            update.append((group_id, external_id, permission))
        # else: already applied with the wanted permission -- nothing to do.

    for external_id, row in sorted(ledger.items()):
        if external_id in desired_by_id:
            continue
        if row.get('state') == 'REVOKED':
            continue
        # Rule 3: only shares the ledger says we applied. The group id used
        # for revocation is re-read from the map so a recreated group heals;
        # if it has gone unmapped meanwhile, that is an error, not a skip --
        # silently keeping a share nobody wants is the worse outcome.
        group_id = resolved.get(external_id, row.get('seafile_group_id'))
        if group_id is None:
            errors.append((external_id,
                           'cannot revoke: group no longer resolvable'))
            continue
        revoke.append((group_id, external_id))

    return SharePlan(add=add, update=update, revoke=revoke, errors=errors)
