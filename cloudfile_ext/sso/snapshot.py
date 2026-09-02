# -*- coding: utf-8 -*-
"""Validate a directory snapshot before the reconciler plans against it.

Decision source: eap-cloudfile docs/review/cloudfile_decision_20260827.md §3.
The directory contract grows three optional fields::

    revision           opaque string; the same revision means the same snapshot,
                       so a sync that sees it again can skip idempotently
    subject_type       'dept' or 'group' (default 'group' when absent)
    parent_external_id external id of the parent dept, or None

With them a snapshot can describe a hierarchy; without them every entry stays
the flat group the previous contract could express. Validation is a separate
module for the same reason the reconciler is: it decides, so it must be free of
Django, seaserv and the database, and testable on plain data.

What validation is for
----------------------

The guards in reconcile.py protect against a *broken feed*. The ones here
protect against a *malformed hierarchy* -- a directory that describes a cycle,
or a sub-department whose parent is missing, or the same external id twice.
Applying any of those would leave Seafile with a group graph the ACL walker
(cloudfile_ext.acl.service._load_subjects) misreads, so the whole snapshot is
rejected and the last good one stays. A snapshot nobody can interpret must
never half-arrive.
"""

DEPT = 'dept'
GROUP = 'group'

#: Fields a directory entry may carry. Everything else is the directory's own
#: business and passes through untouched, so providers can add metadata without
#: a coordinated upgrade.
SUBJECT_TYPE = 'subject_type'
PARENT_EXTERNAL_ID = 'parent_external_id'
REVISION = 'revision'
#: Contract v2 (decision 2026-08-28 §2.3): members are the enterprise userIds
#: the directory is authoritative for, not login strings. `members` (logins)
#: stays valid so providers upgrade independently; when both appear the v2
#: key wins.
MEMBER_USER_IDS = 'member_user_ids'
MEMBERS = 'members'


class SnapshotRejected(Exception):
    """The snapshot is not internally consistent; nothing will be applied.

    Carries the offending detail because a refusal an operator cannot act on
    reads as a sync bug rather than a directory bug.
    """


def normalize_entry(entry):
    """Fold one raw directory entry to the canonical shape.

    Absent optional fields become their defaults (flat group, no parent), so
    providers that have not upgraded continue to work unchanged -- the
    compatibility stage in decision §3.2 is "old shape is valid shape".
    Membership: `member_user_ids` (contract v2, enterprise userIds) when
    present, else the original `members` (login strings). Downstream treats
    either as opaque member strings to resolve; the difference is which
    resolver key answers them, which is the identity layer's business.
    """
    subject_type = (entry.get(SUBJECT_TYPE) or GROUP).strip().lower()
    parent = entry.get(PARENT_EXTERNAL_ID)
    parent = (parent or '').strip() or None
    if entry.get(MEMBER_USER_IDS) is not None:
        members = list(entry.get(MEMBER_USER_IDS) or [])
    else:
        members = list(entry.get(MEMBERS) or [])
    return {
        'external_id': (entry.get('external_id') or '').strip(),
        'name': (entry.get('name') or '').strip(),
        'members': members,
        SUBJECT_TYPE: subject_type,
        PARENT_EXTERNAL_ID: parent,
    }


def validate(snapshot):
    """Return the normalized snapshot, or raise SnapshotRejected.

    Checks, in the order an operator would ask them:

    1. every entry has a non-empty external_id, and no id appears twice --
       a duplicate would make two rows claim one mapping key;
    2. subject_type is 'dept' or 'group' -- anything else is a typo the ACL
       layer would silently treat as a plain group;
    3. only a dept has a parent -- a group with one is a contract mistake,
       since group semantics (role, team) are deliberately flat;
    4. every parent_external_id resolves to a dept *in the same snapshot* --
       a parent outside the feed cannot be keyed by external id, and guessing
       by name is what decision §3.1 forbids;
    5. the dept graph is a forest: no cycles, so a parent chain terminates.
    """
    if not isinstance(snapshot, (list, tuple)):
        raise SnapshotRejected(
            'snapshot must be a list of entries, got %r'
            % type(snapshot).__name__)

    # Defensive: some directory feeds include null placeholders.
    snapshot = [entry for entry in snapshot if entry is not None]
    normalized = [normalize_entry(entry) for entry in snapshot]

    seen = {}
    for entry in normalized:
        external_id = entry['external_id']
        if not external_id:
            raise SnapshotRejected(
                'entry without external_id: %r' % (entry,))
        if external_id in seen:
            raise SnapshotRejected(
                'duplicate external_id %r' % external_id)
        if entry[SUBJECT_TYPE] not in (DEPT, GROUP):
            raise SnapshotRejected(
                'entry %r: subject_type must be %r or %r, got %r'
                % (external_id, DEPT, GROUP, entry[SUBJECT_TYPE]))
        if entry[SUBJECT_TYPE] == GROUP and entry[PARENT_EXTERNAL_ID]:
            raise SnapshotRejected(
                'entry %r: a group must not carry parent_external_id %r; '
                'hierarchy is a dept-only concept'
                % (external_id, entry[PARENT_EXTERNAL_ID]))
        seen[external_id] = entry

    for entry in normalized:
        parent = entry[PARENT_EXTERNAL_ID]
        if parent is None:
            continue
        parent_entry = seen.get(parent)
        if parent_entry is None or parent_entry[SUBJECT_TYPE] != DEPT:
            raise SnapshotRejected(
                'entry %r: parent_external_id %r does not name a dept in '
                'this snapshot' % (entry['external_id'], parent))

    _reject_cycles(normalized, seen)
    return normalized


def _reject_cycles(entries, by_id):
    """Walk each dept's ancestor chain; a revisit means a cycle."""
    for entry in entries:
        if entry[SUBJECT_TYPE] != DEPT:
            continue
        walked = set()
        current = entry
        while current is not None and current[PARENT_EXTERNAL_ID] is not None:
            if current['external_id'] in walked:
                raise SnapshotRejected(
                    'dept cycle at %r' % current['external_id'])
            walked.add(current['external_id'])
            current = by_id.get(current[PARENT_EXTERNAL_ID])


def revision_of(snapshot):
    """The snapshot's revision marker, or None when the feed sends none.

    None is not an error: revision is an optimisation for idempotent skipping,
    and a feed without it simply syncs every tick exactly as before.
    """
    if isinstance(snapshot, dict):
        return (snapshot.get(REVISION) or '').strip() or None
    return None


def dept_order(entries):
    """Topologically order entries so every dept precedes its children.

    The apply layer creates a sub-department by passing its parent's Seafile
    group_id, so a parent must exist first. Parents-before-children is also
    the rule decision §3.1 states. Groups carry no ordering constraint and
    keep their snapshot position.
    """
    by_id = {entry['external_id']: entry for entry in entries}
    ordered, placed = [], set()

    def place(entry):
        if entry['external_id'] in placed:
            return
        parent = entry.get(PARENT_EXTERNAL_ID)
        if parent is not None:
            place(by_id[parent])
        ordered.append(entry)
        placed.add(entry['external_id'])

    for entry in entries:
        place(entry)
    return ordered
