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

#: 逐成员核实时的成员数上限。
#: 修改逻辑/原因（2026-09-17）：角色/普通组自己没被库级分享时，无法据此断言它的成员
#: 进不了这个库（成员可能靠各自部门的库级分享或个人用户分享取得 native 权限），只能
#: 逐个成员问。但一个角色可能有几百人、每次问都是一次 RPC，而这条路只在巡检
#: （annotate_eligibility=true，本来就标注"较慢"）上按需触发。所以给一个硬上限：
#: 超过上限就返回 None（无法判定）—— 部分扫描证明不了"没人被覆盖"，
#: 绝不能因此说 False，否则又会把有效规则标成"永不生效"。
MEMBER_SCAN_LIMIT = 200


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


def parent_group_id_of(group_id, get_group=None):
    """``parent_group_id`` of ``group_id``, or ``None`` when unreadable.

    ``0`` = ordinary group (a role, or a plain group), ``-1`` = top-level
    department, ``>0`` = sub-department whose parent is that id. Three places
    must agree on this classification -- the authoritative C layer
    (``cf-acl.c``, ``build_subject_set``), the Hub's runtime subject set
    (``acl.service._load_subjects``) and this probe -- because the runtime one
    decides which rules a user actually matches. Disagreeing here would make
    the report describe a different rule than the one that runs.

    ``None`` means "could not tell", never "not a group": callers must not
    treat it as either of the two categories.
    """
    try:
        gid = int(group_id)
    except (TypeError, ValueError):
        return None

    if get_group is None:
        try:
            from seaserv import ccnet_api
        except Exception:
            logger.warning('acl granularity: ccnet_api unavailable', exc_info=True)
            return None
        get_group = ccnet_api.get_group

    try:
        group = get_group(gid)
    except Exception:
        logger.warning('acl granularity: get_group(%s) failed', gid, exc_info=True)
        return None
    if group is None:
        return None

    # 缺字段时不默认成 0（0 会被当成"普通组"从而走逐成员核实）：判不出类型就说判不出。
    parent = getattr(group, 'parent_group_id', None)
    if parent is None:
        return None
    try:
        return int(parent)
    except (TypeError, ValueError):
        return None


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
    """Whether ``subject``'s people can already reach the library.

    Three answers on purpose -- callers act on ``False`` (it drives the admin
    UI's batch cleanup), so it must not be guessed:

    * ``True`` -- the group, one of its parent departments, or (for a role /
      plain group, see below) one of its members already has native permission
      on this library;
    * ``False`` -- the subject is a *department* and neither it nor an ancestor
      is shared, so no department share reaches its members: the rule can never
      take effect;
    * ``None`` -- cannot tell (probe failure, unreadable subject, or a member
      scan truncated at ``MEMBER_SCAN_LIMIT``).

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
    if any(str(group_id) in shared for group_id in group_ids):
        return True

    # 修改逻辑/原因（2026-09-17）：主体自己没被分享，**不等于**它的人进不了这个库。
    # 角色/普通组（parent_group_id == 0）没有部门父链，它的成员是靠**各自所在部门**的
    # 库级分享（部门分享对子部门成员生效），或个人的用户分享，才拿到 native 权限的
    # —— 这两种轴按"主体"探针都看不见。原先这里直接返回 False，于是"其实生效"的角色
    # 规则被巡检标成"永不生效"，还会被门户"一键删除失效规则"当成坏规则清掉
    # （实测：库 3a000c19-… 上 group 1245 的 /技术部/技术管理处 rw 规则，
    #   成员经技术部拿到库级权限，规则确实生效，却被判为无资格）。
    # 所以普通组/角色逐成员核实；部门（parent_group_id != 0）维持原判定 ——
    # 部门链本身就是它的成员轴，链上都没分享才是真的没资格。
    parent = parent_group_id_of(subject)
    if parent is None:
        # 连主体是"普通组/角色"还是"部门"都判不出来：与 share 读失败同理，
        # 只能回"无法判定"，不能替它下"永不生效"的结论。
        return None
    if parent != 0:
        return False
    return _member_reaches_library(repo_id, subject)


def _member_reaches_library(repo_id, group_id, member_lister=None,
                            user_permission=None, limit=None):
    """Whether any member of ``group_id`` already has native permission here.

    The sound way to answer "can this role's rule ever affect anyone": a role
    is not an access axis of its own -- its members reach a library through
    their departments or their personal shares -- so the subject's own share
    state says nothing about them. Asked per member with the very same call the
    ``user`` probe uses (``check_permission_by_path`` at the library root), so
    the two subject types cannot drift apart.

    ``member_lister`` is called as ``(group_id, start, limit)``, matching
    ``ccnet_api.get_group_members``.

    Returns True / False / None-unknown. Unknown also covers a member list
    truncated at ``limit``: with only part of the members checked, "nobody
    matched" cannot prove the negative, and answering False would re-create the
    false "never effective" flag this scan exists to remove. A failing
    per-member check is left to propagate, so the caller degrades to unknown
    rather than to a dead-rule verdict.
    """
    if limit is None:
        limit = MEMBER_SCAN_LIMIT
    if member_lister is None:
        from seaserv import ccnet_api
        member_lister = ccnet_api.get_group_members
    if user_permission is None:
        user_permission = _user_permission

    # 多取一条：用来区分"扫完了"与"被上限截断"，这两种情况的结论不同。
    members = list(member_lister(int(group_id), 0, limit + 1) or ())
    # ccnet_api 返回带 user_name 的对象；也接受裸字符串，便于测试与老调用方。
    for member in members[:limit]:
        username = getattr(member, 'user_name', None) or member
        if user_permission(repo_id, username) is not None:
            return True
    return None if len(members) > limit else False


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
