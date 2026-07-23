# -*- coding: utf-8 -*-
"""Turn a directory snapshot into a list of changes to make.

This module is the whole of the interesting part of SSO group mapping, and it
is deliberately free of Django, seaserv and the database: it takes plain data
in and returns plain data out, so the case set in
cloudfile-docker/docs/sso-cases.json can drive it directly and every guard
below can be tested without a running server.

The shape mirrors cloudfile_ext.acl.resolver for the same reason -- the part
that decides *what* should happen must be checkable on its own, separately
from the part that makes it happen.

What it is allowed to touch
---------------------------

Only groups CloudFile itself created, which are exactly the ones recorded in
``cf_sso_group_map``. A group an administrator made by hand is never renamed,
never emptied, never joined. This is not politeness: Seafile groups own
libraries, so a sync that adopted an existing group could hand a directory's
worth of people access to data nobody meant to share.

Within a mapped group, membership *is* the directory's -- that is what the
mapping means, and a "merge" rule would leave no way to remove anyone.

Why a plan can be refused outright
----------------------------------

The failure that matters here is not a wrong member, it is a directory call
that succeeds and returns nothing: an expired token, a renamed endpoint, a
proxy answering 200 with an empty body. Treated literally, an empty snapshot
means "every group is now empty", and the sync would faithfully remove every
member of every mapped group -- silently, with a 200 in the log.

So two guards, both here rather than in the caller, so both are testable:

1. An empty snapshot against a non-empty map is refused. There is no way to
   distinguish "the directory really has no groups" from "the call failed
   upwards", and one of those two readings destroys data.
2. A plan that would remove more than ``max_removal_ratio`` of currently
   mapped memberships is refused. Legitimate directory changes are gradual;
   losing half of everyone in one tick is a broken feed, not a reorganisation.

Both are refusals, not warnings. A sync that "mostly worked" leaves the
deployment in a state nobody chose and nobody can name.
"""


class SyncRefused(Exception):
    """The plan was rejected wholesale by a guard.

    Carries the numbers that triggered it, because the operator's next
    question is always "how far off was it?" -- and because a refusal with no
    figures reads as a bug in the sync rather than a fact about the feed.
    """


#: Refuse when a single tick would drop more than this share of the
#: memberships CloudFile currently manages. Half is high enough that ordinary
#: churn never trips it and low enough that a truncated feed does.
DEFAULT_MAX_REMOVAL_RATIO = 0.5


def normalize(identity):
    """Fold an identity to the form membership is compared in.

    Directory exports are written by humans and by other systems, so the same
    person arrives as ``Alice@Example.com`` one day and ``alice@example.com``
    the next. Comparing them raw makes that look like "one member left, a
    different one joined" -- churn the sync would dutifully apply, twice per
    tick, forever.
    """
    return (identity or '').strip().lower()


class Plan(object):
    """What a sync would do, before any of it is done.

    Kept as data rather than executed inline so the guards can look at the
    whole thing, and so an operator can be shown it (the admin status endpoint
    reports a dry-run plan) without anything changing.
    """

    def __init__(self):
        self.create = []   # [{'external_id', 'name', 'members'}]
        self.rename = []   # [{'group_id', 'name'}]
        self.add = []      # [{'group_id', 'identity'}]
        self.remove = []   # [{'group_id', 'identity'}]
        self.unmap = []    # [{'external_id', 'group_id'}]

    @property
    def empty(self):
        return not (self.create or self.rename or self.add or self.remove
                    or self.unmap)

    def counts(self):
        """Summary for logs and the status endpoint."""
        return {
            'create': len(self.create),
            'rename': len(self.rename),
            'add': len(self.add),
            'remove': len(self.remove),
            'unmap': len(self.unmap),
        }

    def __repr__(self):                                     # pragma: no cover
        return '<Plan %r>' % (self.counts(),)


def build(snapshot, mapped, members, protected=None,
          max_removal_ratio=DEFAULT_MAX_REMOVAL_RATIO):
    """Return the Plan that makes `members` match `snapshot`.

    ``snapshot``   what the directory says: a list of
                   ``{'external_id', 'name', 'members': [identity, ...]}``.
                   Members are already resolved to the identity enforcement
                   compares (cloudfile_ext.acl.subjects); anything that could
                   not be resolved has been dropped by the caller and reported
                   separately, so an unknown account is a line in the sync
                   report rather than a member silently removed.
    ``mapped``     ``{external_id: {'group_id': int, 'name': str}}`` -- the
                   groups CloudFile has created before, i.e. the only ones it
                   may touch.
    ``members``    ``{group_id: [identity, ...]}`` -- who is in those groups now.
    ``protected``  ``{group_id: [identity, ...]}`` never to be removed. In
                   practice the group's creator: Seafile groups need an owner,
                   and a directory that does not list the service account
                   would otherwise ask us to remove it on the first tick.

    Raises SyncRefused if a guard rejects the result -- see the module
    docstring for why that is a refusal rather than a partial apply.
    """
    protected = protected or {}

    if not snapshot and mapped:
        raise SyncRefused(
            'directory returned no groups while %d are mapped; refusing to '
            'empty them. An empty snapshot and a failed call look identical '
            'from here, and only one of the two readings is recoverable.'
            % len(mapped))

    plan = Plan()
    seen = set()

    for group in snapshot:
        external_id = (group.get('external_id') or '').strip()
        if not external_id:
            # Without a stable id there is nothing to map against: matching on
            # the display name instead would re-create every group the moment
            # the directory renames one.
            raise SyncRefused('directory group without external_id: %r' % (group,))

        seen.add(external_id)
        wanted = _unique(normalize(m) for m in group.get('members') or [])
        name = (group.get('name') or external_id).strip()

        existing = mapped.get(external_id)
        if existing is None:
            plan.create.append({
                'external_id': external_id,
                'name': name,
                'members': wanted,
            })
            continue

        group_id = existing['group_id']
        if name and name != existing.get('name'):
            plan.rename.append({'group_id': group_id, 'name': name})

        current = _unique(normalize(m) for m in members.get(group_id) or [])
        keep = set(normalize(m) for m in protected.get(group_id) or [])

        current_set = set(current)
        wanted_set = set(wanted)

        for identity in wanted:
            if identity not in current_set:
                plan.add.append({'group_id': group_id, 'identity': identity})
        for identity in current:
            if identity not in wanted_set and identity not in keep:
                plan.remove.append({'group_id': group_id, 'identity': identity})

    for external_id, row in sorted(mapped.items()):
        if external_id not in seen:
            # The group is gone from the directory, but the Seafile group may
            # own libraries and be shared into. Dropping the mapping stops it
            # being synced; deleting it is a decision only a human should make,
            # and one no sync tick should be able to take by accident.
            plan.unmap.append({'external_id': external_id,
                               'group_id': row['group_id']})

    _check_removal_ratio(plan, members, max_removal_ratio)
    return plan


def _check_removal_ratio(plan, members, max_removal_ratio):
    """Refuse a plan that removes an implausible share of managed members."""
    if max_removal_ratio is None:
        return

    total = sum(len(_unique(normalize(m) for m in group or []))
                for group in members.values())
    if not total:
        return

    ratio = len(plan.remove) / float(total)
    if ratio > max_removal_ratio:
        raise SyncRefused(
            'plan removes %d of %d managed memberships (%.0f%%, limit %.0f%%); '
            'refusing. Raise CF_SSO_MAX_REMOVAL_RATIO if the directory really '
            'did change this much.'
            % (len(plan.remove), total, ratio * 100, max_removal_ratio * 100))


def _unique(values):
    """Deduplicate while keeping order, so plans are stable between runs.

    Order matters more than it looks: the sync report and the dry-run plan are
    compared between ticks by operators, and a set's iteration order would make
    two identical plans look different.
    """
    out = []
    seen = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out
