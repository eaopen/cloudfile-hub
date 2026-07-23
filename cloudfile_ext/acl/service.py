# -*- coding: utf-8 -*-
"""Directory ACL enforcement at the Hub layer.

``apply_dir_acl`` is what the patched ``seahub.views.check_folder_permission``
delegates to. That one function is called 353 times across Seahub -- web views,
REST endpoints, thumbnails, metadata -- so hooking it covers every Hub entry
point at once.

This is *not* the authoritative check. seafile-server enforces the same rules
below the Hub so that WebDAV and the desktop sync client cannot go around it.
"""

import logging

from django.conf import settings
from django.core.cache import cache

from cloudfile_ext.features import is_enabled
from cloudfile_ext.acl import resolver

logger = logging.getLogger(__name__)

RULES_CACHE_KEY = 'cf_acl_rules_%s'
SUBJECTS_CACHE_KEY = 'cf_acl_subjects_%s'


def _cache_ttl():
    return getattr(settings, 'CF_ACL_CACHE_TTL', 30)


def _load_rules(repo_id):
    key = RULES_CACHE_KEY % repo_id
    rules = cache.get(key)
    if rules is None:
        from cloudfile_ext.acl.models import DirACL
        rules = DirACL.objects.rules_for_repo(repo_id)
        cache.set(key, rules, _cache_ttl())
    return rules


def invalidate_repo(repo_id):
    """Drop the cached rules for a repo. Call after any rule write."""
    cache.delete(RULES_CACHE_KEY % repo_id)


def _load_subjects(username):
    """Subjects for a user: the user, their groups, their departments.

    Department ancestors are walked explicitly rather than trusting group
    membership to be transitive, because a rule on a parent department has to
    apply to members of its sub-departments (acl-semantics.md section 3).
    """
    key = SUBJECTS_CACHE_KEY % username
    cached = cache.get(key)
    if cached is not None:
        return cached

    from seaserv import ccnet_api

    group_ids, dept_ids = [], []
    for group in ccnet_api.get_groups(username) or ():
        # parent_group_id: 0 = ordinary group, -1 = top-level department,
        # >0 = sub-department whose parent is that id.
        if group.parent_group_id == 0:
            group_ids.append(group.id)
            continue

        dept_ids.append(group.id)
        parent_id = group.parent_group_id
        seen = {group.id}
        while parent_id and parent_id > 0 and parent_id not in seen:
            seen.add(parent_id)
            dept_ids.append(parent_id)
            parent = ccnet_api.get_group(parent_id)
            if parent is None:
                break
            parent_id = parent.parent_group_id

    subjects = resolver.subject_set(username, group_ids, dept_ids)
    cache.set(key, subjects, _cache_ttl())
    return subjects


def invalidate_user(username):
    """Drop a user's cached subject set. Call after group membership changes."""
    cache.delete(SUBJECTS_CACHE_KEY % username)


def apply_dir_acl(username, repo_id, path, permission):
    """Narrow `permission` according to the directory ACL.

    Returns the permission unchanged when the feature is off, so that a
    CloudFile build with every switch off behaves exactly like native CE.
    """
    if not is_enabled('CF_ENABLE_DIR_ACL'):
        return permission

    if permission is None or not username:
        return permission

    try:
        rules = _load_rules(repo_id)
    except Exception:
        # Fail closed. This is a security control, and seafile-server would
        # deny the actual data access anyway; letting the Hub fall open here
        # would leak directory names that an `invisible` rule is meant to hide.
        logger.exception(
            'cloudfile: failed to load directory ACL for repo %s, denying '
            'access', repo_id)
        return None

    if not rules:
        return permission

    try:
        subjects = _load_subjects(username)
    except Exception:
        logger.exception(
            'cloudfile: failed to resolve subjects for %s, denying access',
            username)
        return None

    return resolver.resolve(rules, subjects, path, permission)
