# -*- coding: utf-8 -*-
"""Legacy v0.8 directory-ACL service -- readers retired, manage stubs remain.

修改逻辑（2026-10-15 v0.9-only）：``apply_dir_acl`` / ``is_path_denied`` /
``_load_rules`` 已删除——统一 ``cf_dir_acl`` 无 ``subject`` 列，这些读取器在
每次调用上失败并对所有库 fail-closed。目录级内容裁决由 v0.9 唯一负责
（seafile-server scoped 核心 + ``cloudfile_extensions.authorization``）。

本模块只保留尚未删除的 legacy 管理视图所需的 ``can_manage`` 及其加载/缓存
辅助；这些视图不再注册路由，随 v0.8 清理一并退出。
"""

import logging
from contextlib import contextmanager
from contextvars import ContextVar
from uuid import uuid4

from django.conf import settings
from django.core.cache import cache

from cloudfile_ext.features import is_enabled
from cloudfile_ext.acl import resolver

logger = logging.getLogger(__name__)

RULES_CACHE_KEY = 'cf_acl_rules_%s'
ADMIN_RULES_CACHE_KEY = 'cf_acl_admin_rules_%s'
SUBJECTS_CACHE_KEY = 'cf_acl_subjects_%s'
RULES_GENERATION_KEY = 'cf_acl_generation_%s'

# One directory response reuses the same raw inputs, not user decisions.
# The context is discarded after the request so writes keep their normal checks.
_page_inputs = ContextVar('cf_acl_page_inputs', default=None)


@contextmanager
def directory_inputs():
    token = _page_inputs.set({})
    try:
        yield
    finally:
        _page_inputs.reset(token)


def _cache_ttl():
    return getattr(settings, 'CF_ACL_CACHE_TTL', 60)



def _load_admin_rules(repo_id):
    key = ADMIN_RULES_CACHE_KEY % repo_id
    local = _page_inputs.get()
    if local is not None and key in local:
        return local[key]
    # A writer switches the namespace: an in-flight old DB read cannot refill
    # the newly invalidated cache. Old generations expire with the normal TTL.
    generation = cache.get(RULES_GENERATION_KEY % repo_id, '0')
    shared_key = key + ':' + generation
    rules = cache.get(shared_key)
    if rules is None:
        from cloudfile_ext.acl.models import DirAdmin
        rules = DirAdmin.objects.rules_for_repo(repo_id)
        cache.set(shared_key, rules, _cache_ttl())
    if local is not None:
        local[key] = rules
    return rules


def invalidate_repo(repo_id):
    """Drop the cached rules for a repo. Call after any rule write."""
    local = _page_inputs.get()
    if local is not None:
        local.clear()
    cache.set(RULES_GENERATION_KEY % repo_id, uuid4().hex, None)
    cache.delete(RULES_CACHE_KEY % repo_id)
    cache.delete(ADMIN_RULES_CACHE_KEY % repo_id)


def _load_subjects(username):
    """Subjects for a user: the user, their groups, their departments.

    Department ancestors are walked explicitly rather than trusting group
    membership to be transitive, because a rule on a parent department has to
    apply to members of its sub-departments (acl-semantics.md section 3).
    """
    key = SUBJECTS_CACHE_KEY % username
    local = _page_inputs.get()
    if local is not None and key in local:
        return local[key]
    cached = cache.get(key)
    if cached is not None:
        if local is not None:
            local[key] = cached
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
    if local is not None:
        local[key] = subjects
    return subjects


def invalidate_user(username):
    """Drop a user's cached subject set. Call after group membership changes."""
    local = _page_inputs.get()
    if local is not None:
        local.pop(SUBJECTS_CACHE_KEY % username, None)
    cache.delete(SUBJECTS_CACHE_KEY % username)




def _is_library_admin(username, repo_id):
    """Library-level adminship: owner or designated admin (V1 of the manage
    dimension). Kept behind a function so tests can stub it without importing
    seahub's share utils."""
    from seahub.share.utils import is_repo_admin
    return is_repo_admin(username, repo_id)


def can_manage(username, repo_id, path):
    """The single management-decision entry point (acl-semantics.md 7.2).

    A library admin always manages; otherwise a directory-level admin grant
    covering `path` does. Management authorization never consults the content
    ACL, so a restrictive content rule can never lock an admin out of the very
    endpoint needed to remove it.
    """
    if _is_library_admin(username, repo_id):
        return True

    if not is_enabled('CF_ENABLE_DIR_ACL'):
        return False

    try:
        rules = _load_admin_rules(repo_id)
    except Exception:
        # Fail closed: not being able to read the grants must not widen who
        # can manage.
        logger.exception(
            'cloudfile: failed to load directory admin grants for repo %s, '
            'denying manage', repo_id)
        return False

    if not rules:
        return False

    try:
        subjects = _load_subjects(username)
    except Exception:
        logger.exception(
            'cloudfile: failed to resolve subjects for %s, denying manage',
            username)
        return False

    return resolver.can_manage(rules, subjects, path)
