# -*- coding: utf-8 -*-
"""Django/RPC probes behind the granularity policy.

Thin on purpose: everything with policy content lives in
``cloudfile_ext.acl.granularity`` (Django-free, unit-tested). This module only
answers two factual questions the policy needs:

* is the rule's path the library root, a directory, or a file?
* can the rule's subject ever be affected -- i.e. does that subject already
  have native (share) permission on the library?

Both are best-effort: ``subject_eligible`` returns ``None`` when it cannot tell
(a probe failure must not block administrators), and callers treat ``None`` as
"allow and do not annotate a warning".
"""

import logging

logger = logging.getLogger(__name__)


def path_kind(repo_id, path, file_probe=None, dir_probe=None):
    """'root' | 'dir' | 'file' for ``path`` in ``repo_id``.

    ``file_probe``/``dir_probe`` are injectable for tests; by default they ask
    seafile_api. The root is reported as 'root' so callers can distinguish
    "whole library" from "a folder" in reports.
    """
    if path is None or path.strip() in ('', '/'):
        return 'root'

    if file_probe is None or dir_probe is None:
        from seaserv import seafile_api
        file_probe = file_probe or (lambda r, p: seafile_api.get_file_id_by_path(r, p))
        dir_probe = dir_probe or (lambda r, p: seafile_api.get_dir_id_by_path(r, p))

    try:
        if file_probe(repo_id, path):
            return 'file'
        if dir_probe(repo_id, path):
            return 'dir'
    except Exception:
        logger.warning('acl granularity: path probe failed for %s/%s',
                       repo_id, path, exc_info=True)
    return 'dir'


def dept_ancestor_ids(group_id, get_group=None):
    """``group_id`` plus every parent department id above it.

    Department membership is inherited: a share with a top-level department
    applies to members of its sub-departments (the subject expansion in
    ``acl.service._load_subjects`` walks the same chain), so eligibility has to
    as well -- otherwise a rule for a sub-department member would be reported
    ineligible while it actually applies.
    """
    if get_group is None:
        from seaserv import ccnet_api
        get_group = ccnet_api.get_group

    ids = []
    try:
        gid = int(group_id)
    except (TypeError, ValueError):
        return ids

    seen = set()
    current = gid
    while current and current > 0 and current not in seen:
        seen.add(current)
        ids.append(current)
        try:
            group = get_group(current)
        except Exception:
            logger.warning('acl granularity: get_group(%s) failed', current,
                           exc_info=True)
            break
        if group is None:
            break
        parent = getattr(group, 'parent_group_id', 0) or 0
        current = parent if parent > 0 else 0
    return ids


def subject_eligible(repo_id, subject_type, subject, probes=None):
    """Whether ``subject`` already has native permission on the library.

    Returns True / False / None-unknown. ``probes`` may inject
    ``{'user_permission': fn, 'group_shared': fn}`` for tests.
    """
    probes = probes or {}
    try:
        if subject_type == 'user':
            user_permission = probes.get('user_permission') or _user_permission
            return user_permission(repo_id, subject) is not None
        group_shared = probes.get('group_shared') or _group_shared
        return group_shared(repo_id, subject)
    except Exception:
        logger.warning('acl granularity: eligibility probe failed for %s/%s:%s',
                       repo_id, subject_type, subject, exc_info=True)
        return None


def _user_permission(repo_id, username):
    """Native permission of another user at the library root.

    ``check_permission_by_path`` takes the username explicitly, which is what
    lets the Hub answer "would this rule ever affect that person" without
    impersonating them.
    """
    from seaserv import seafile_api
    return seafile_api.check_permission_by_path(repo_id, '/', username)


def _group_shared(repo_id, subject):
    """Whether the group -- or a parent department -- is shared on the library."""
    from seahub.share.models import RepoGroup

    group_ids = dept_ancestor_ids(subject)
    if not group_ids:
        return None
    if RepoGroup.objects.filter(repo_id=repo_id, group_id__in=group_ids).exists():
        return True

    # Organisational shares live in their own table on Seafile 14; absent
    # models (or orgs disabled) must not turn into a false "ineligible".
    try:
        from seahub.share.models import OrgGroupRepo
        return OrgGroupRepo.objects.filter(
            repo_id=repo_id, group_id__in=group_ids).exists()
    except Exception:
        return False
