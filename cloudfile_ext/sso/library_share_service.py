# -*- coding: utf-8 -*-
"""Apply what cloudfile_ext.sso.library_share_policy decided.

Everything that touches seaserv lives here, behind the same guardrails the
decision (2026-08-27 §4.4; revision gate 2026-08-28 §8.2) fixed:

*   a share is applied under the repo owner's identity, via the same
    seafile_api the admin endpoint uses, so caches, events and quota follow;
*   revocation touches only rows the ledger claims;
*   an unmapped id or a failed call records ERROR and leaves the previous
    state standing -- never a blanket cleanup that treats an exception as an
    empty desired state;
*   a PUT carries the ``policy_revision`` its expectation was computed from,
    and an older revision is rejected outright: a delayed retry must never
    overwrite a newer policy with stale shares.
"""

import logging
import time

from cloudfile_ext.sso import library_share_policy
from cloudfile_ext.sso.library_shares import ManagedLibraryShare
from cloudfile_ext.sso.models import SSOGroupMap
from cloudfile_ext.sso.service import PROVIDER

logger = logging.getLogger(__name__)

#: Table and row guard for the per-repo highest-accepted revision. Kept as a
#: tiny module-level seam so the gate is testable without the ORM.
REVISION_TABLE = 'cf_library_share_revision'


class StaleRevision(Exception):
    """The PUT's policy_revision is older than one already applied.

    Carries both revisions because the caller's next question is always
    "what does the server actually have, and what did I send?".
    """

    def __init__(self, accepted, rejected=None):
        self.accepted = accepted
        self.rejected = rejected
        super().__init__(
            'policy_revision %s is older than the applied revision %s'
            % (rejected if rejected is not None else '?', accepted))


def _connection():
    """The seafile-db connection cf_* tables live on.

    ``cf_library_share_revision`` (like every cf_* table) is created in
    seafile-db by cloudfile-server/scripts/sql and reached through the
    ``cloudfile`` alias the router resolves for cloudfile_ext models. Raw SQL
    here must use that same connection; ``from django.db import connection``
    gives the ``default`` (seahub-db) connection, where the table does not
    exist, and the resulting ProgrammingError was surfacing as an uncaught
    500 on the desired-state PUT.
    """
    from django.db import connections
    from cloudfile_ext.db_router import _alias
    return connections[_alias()]


def _read_accepted_revision(repo_id):
    with _connection().cursor() as cursor:
        cursor.execute(
            'SELECT policy_revision FROM %s WHERE provider = %%s '
            'AND repo_id = %%s' % REVISION_TABLE,
            [PROVIDER, repo_id])
        row = cursor.fetchone()
    return row[0] if row else None


def _record_revision(repo_id, revision):
    now = int(time.time())
    with _connection().cursor() as cursor:
        cursor.execute(
            'INSERT INTO %s (provider, repo_id, policy_revision, ctime, '
            'mtime) VALUES (%%s, %%s, %%s, %%s, %%s) ON DUPLICATE KEY '
            'UPDATE policy_revision = VALUES(policy_revision), '
            'mtime = VALUES(mtime)' % REVISION_TABLE,
            [PROVIDER, repo_id, revision, now, now])


def check_revision(repo_id, revision):
    """Raise :class:`StaleRevision` when ``revision`` is already outdated.

    ``revision`` of None keeps the old contract (unversioned PUTs are always
    accepted), for callers that have not adopted the field yet.
    """
    if revision is None:
        return
    revision = int(revision)
    accepted = _read_accepted_revision(repo_id)
    if accepted is not None and revision < int(accepted):
        raise StaleRevision(int(accepted), revision)


def _resolved_groups():
    """``{external_group_id: seafile_group_id}`` from the live group map."""
    return {external_id: row['group_id']
            for external_id, row
            in SSOGroupMap.objects.as_dict(PROVIDER).items()}


def _seafile_api():
    # Imported lazily so the gate (and anything above it) stays importable and
    # testable without a running seaserv.
    from seaserv import seafile_api
    return seafile_api


def _repo_owner(repo_id):
    return _seafile_api().get_repo_owner(repo_id)


def plan_for(repo_id, desired):
    """Build the plan for one repo. Read-only; used by dry-run and apply."""
    ledger = ManagedLibraryShare.objects.as_dict(repo_id)
    resolved = _resolved_groups()
    return library_share_policy.build(desired, ledger, resolved)


def apply(repo_id, desired, policy_revision=None):
    """Apply the plan and record the outcome. Returns a report dict.

    Never raises past an individual operation: one group that cannot be
    resolved must not stop the others, and the report is what the caller
    shows and stores. A stale ``policy_revision`` is the one whole-request
    refusal: the caller must recompute from the newer policy, not partially
    apply a mix of generations.
    """
    check_revision(repo_id, policy_revision)

    seafile_api = _seafile_api()

    plan = plan_for(repo_id, desired)
    applied = {'add': 0, 'update': 0, 'revoke': 0}
    errors = [('%s: %s' % (ext, reason)) for ext, reason in plan.errors]

    owner = _repo_owner(repo_id)
    if not owner:
        return {'error': 'repo %s has no owner; nothing applied' % repo_id}

    for group_id, external_id, permission in plan.add:
        try:
            seafile_api.set_group_repo(repo_id, group_id, owner, permission)
            ManagedLibraryShare.objects.record_applied(
                repo_id, external_id, group_id, permission)
            applied['add'] += 1
        except Exception as exc:
            ManagedLibraryShare.objects.record_error(
                repo_id, external_id, exc)
            errors.append('add %s: %s' % (external_id, exc))

    for group_id, external_id, permission in plan.update:
        # Seafile's share is idempotent on (repo, group): re-sharing updates
        # the permission in place, which is exactly the drift fix wanted.
        try:
            seafile_api.set_group_repo(repo_id, group_id, owner, permission)
            ManagedLibraryShare.objects.record_applied(
                repo_id, external_id, group_id, permission)
            applied['update'] += 1
        except Exception as exc:
            ManagedLibraryShare.objects.record_error(
                repo_id, external_id, exc)
            errors.append('update %s: %s' % (external_id, exc))

    for group_id, external_id in plan.revoke:
        try:
            seafile_api.unset_group_repo(repo_id, group_id, owner)
            ManagedLibraryShare.objects.record_revoked(repo_id, external_id)
            applied['revoke'] += 1
        except Exception as exc:
            ManagedLibraryShare.objects.record_error(
                repo_id, external_id, exc)
            errors.append('revoke %s: %s' % (external_id, exc))

    report = {'applied': applied,
              'errors': errors[:20],
              'planned': {'add': len(plan.add), 'update': len(plan.update),
                          'revoke': len(plan.revoke)}}
    if policy_revision is not None:
        try:
            _record_revision(repo_id, int(policy_revision))
        except Exception as exc:                        # pragma: no cover
            # Shares are applied; failing to bump the marker must not
            # roll them back, but it must be visible.
            logger.error('recording policy_revision for %s failed: %s',
                         repo_id, exc)
            report['revision_recorded'] = False
        else:
            report['revision'] = int(policy_revision)
    return report
