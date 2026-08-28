# -*- coding: utf-8 -*-
"""Apply what cloudfile_ext.sso.library_share_policy decided.

Everything that touches seaserv lives here, behind the same guardrails the
decision (2026-08-27 §4.4) fixed:

*   a share is applied under the repo owner's identity, via the same
    seafile_api the admin endpoint uses, so caches, events and quota follow;
*   revocation touches only rows the ledger claims;
*   an unmapped id or a failed call records ERROR and leaves the previous
    state standing -- never a blanket cleanup that treats an exception as an
    empty desired state.
"""

import logging

from cloudfile_ext.sso import library_share_policy
from cloudfile_ext.sso.library_shares import ManagedLibraryShare
from cloudfile_ext.sso.models import SSOGroupMap
from cloudfile_ext.sso.service import PROVIDER

logger = logging.getLogger(__name__)


def _resolved_groups():
    """``{external_group_id: seafile_group_id}`` from the live group map."""
    return {external_id: row['group_id']
            for external_id, row
            in SSOGroupMap.objects.as_dict(PROVIDER).items()}


def _repo_owner(repo_id):
    from seaserv import seafile_api
    return seafile_api.get_repo_owner(repo_id)


def plan_for(repo_id, desired):
    """Build the plan for one repo. Read-only; used by dry-run and apply."""
    ledger = ManagedLibraryShare.objects.as_dict(repo_id)
    resolved = _resolved_groups()
    return library_share_policy.build(desired, ledger, resolved)


def apply(repo_id, desired):
    """Apply the plan and record the outcome. Returns a report dict.

    Never raises past an individual operation: one group that cannot be
    resolved must not stop the others, and the report is what the caller
    shows and stores.
    """
    from seaserv import seafile_api

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
    return report
