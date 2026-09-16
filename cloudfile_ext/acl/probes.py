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


def _group_shared(repo_id, subject, share_lister=None, org_id=None):
    """Whether the group -- or a parent department -- is shared on the library.

    Reads the share tables through ``SeafileDB`` (raw SQL) instead of the
    ``RepoGroup`` Django model. Seafile 14 removed ``RepoGroup`` -- and
    ``OrgGroupRepo`` -- from ``seahub.share.models`` (the tables themselves are
    still there), so the old ``import`` raised ``ImportError``, got swallowed by
    ``subject_eligible``'s broad ``except``, and *every* department/group probe
    silently degraded to unknown. That also switched off the write-time
    eligibility check (``granularity.check_eligibility``) for those subjects, so
    rules that can never take effect were stored without complaint -- and the
    report could not flag them either. ``db_api.SeafileDB`` is the supported
    reader and is what ``/api2/.../share-info/`` itself uses.

    ``share_lister`` / ``org_id`` are injectable for tests, like the other
    probes here. Errors are deliberately left to propagate: ``subject_eligible``
    converts them into ``None`` ("cannot tell") rather than a false
    "ineligible".
    """
    group_ids = dept_ancestor_ids(subject)
    if not group_ids:
        # 祖先链都取不到（主体不是合法的部门/群组 id）→ 无法判定。
        # 必须是 None 而不是 False：False 会被 granularity.check_eligibility 当成
        # "明确无库级资格"而拒绝写入，等于用一次失败的探测去禁掉管理员的正常操作。
        return None

    if share_lister is None:
        # 修改逻辑/原因（2026-09-16）：原实现首行是
        # `from seahub.share.models import RepoGroup`，但 Seafile 14 已把 RepoGroup /
        # OrgGroupRepo 从 share/models.py 移除（只删了模型，表还在），该 import 必抛
        # ImportError；异常被 subject_eligible 的宽 except 吞成 None，于是 **所有**
        # dept/group 主体的资格恒为"未知"——写入侧资格校验与巡检标注一起静默失效，
        # 这正是"配置了却永不生效的部门规则"查不出来的原因。
        # SeafileDB 用裸 SQL 读同名表，是 /api2/.../share-info/ 接口本身在用的读法。
        from seahub.utils.db_api import SeafileDB
        share_lister = SeafileDB().get_repo_group_share_list
    if org_id is None:
        # get_repo_group_share_list 以 org_id 真假决定读 RepoGroup 还是 OrgGroupRepo 两张表，
        # 而探针里没有 request 上下文，只能从库反查组织号（见 _repo_org_id）。
        org_id = _repo_org_id(repo_id)

    # share_to 来自数据库列（可能是 int），而组 id 从 URL / 表单进来是 str，统一成 str 再比。
    # 这里不吞异常：读失败就往上冒，由 subject_eligible 记日志并返回 None（无法判定），
    # 绝不能降级成 False —— 那会把仍然有效的规则判死，前端"一键删除失效规则"还会真删掉。
    share_list = share_lister(repo_id, org_id)
    shared = {str(info.get('share_to')) for info in share_list}
    return any(str(group_id) in shared for group_id in group_ids)


def _repo_org_id(repo_id):
    """Org id of the library, or '' when the deployment has no organisations.

    ``get_repo_group_share_list`` picks the ``RepoGroup`` or ``OrgGroupRepo``
    table from this value, and there is no request context here to read it from,
    so it has to come from the repo. A failed lookup is not fatal: '' keeps the
    common non-org path working.
    """
    try:
        from seaserv import get_org_id_by_repo_id
        org_id = int(get_org_id_by_repo_id(repo_id) or 0)
    except Exception:
        # 取不到组织号不算失败：'' 走非组织表，覆盖未启用组织的常规部署；
        # 真读不到时下游会抛错并冒泡成 None（"无法判定"），不会误判成"无资格"。
        logger.warning('acl granularity: org lookup failed for %s', repo_id,
                       exc_info=True)
        return ''
    # 0（未启用组织，见实测）与负数（查询失败）一律按非组织处理，
    # 否则会去读只存在于组织部署里的 OrgGroupRepo 表。
    return org_id if org_id > 0 else ''
