# -*- coding: utf-8 -*-
"""System-admin endpoints for directory ACL.

Separate from apis.py because these bypass library ownership: an
administrator has to be able to inspect and repair ACL on libraries they do
not own, including ones whose owner has left.

报文中文化同 apis.py 顶部说明（2026-09-16）：本模块返回的报文也是中文，
其中 `page or per_page invalid.` / `Library not found.` / `Internal Server Error`
在别的模块有同名副本，本次只改 ACL 这一份，不回改别处。
"""

import logging

from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView

from seaserv import seafile_api

from seahub.api2.authentication import TokenAuthentication
from seahub.api2.throttling import UserRateThrottle
from seahub.api2.utils import api_error

from cloudfile_ext.features import is_enabled
from cloudfile_ext.acl import granularity, probes, resolver, service, subjects
from cloudfile_ext.acl.apis import (
    VALID_PERMISSIONS, VALID_SUBJECT_TYPES, _serialize, _serialize_admin,
    _feature_off,
)

logger = logging.getLogger(__name__)

#: A repo can accumulate a lot of rules; cap one response so an admin listing
#: cannot turn into an accidental full-table scan.
MAX_RULES_PER_PAGE = 500


class AdminDirACLView(APIView):
    """List every rule in a library, or replace a rule, as an administrator."""

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser,)
    throttle_classes = (UserRateThrottle,)

    def get(self, request, repo_id):
        if not is_enabled('CF_ENABLE_DIR_ACL'):
            return _feature_off()

        from cloudfile_ext.acl.models import DirACL

        try:
            page = int(request.GET.get('page', '1'))
            per_page = min(int(request.GET.get('per_page', '100')),
                           MAX_RULES_PER_PAGE)
        except ValueError:
            return api_error(status.HTTP_400_BAD_REQUEST,
                             'page 或 per_page 不合法。')
        if page < 1 or per_page < 1:
            return api_error(status.HTTP_400_BAD_REQUEST,
                             'page 或 per_page 不合法。')

        qs = DirACL.objects.filter(repo_id=repo_id).order_by('path', 'id')
        total = qs.count()
        start = (page - 1) * per_page
        rules = qs[start:start + per_page]

        serialized = [_serialize(r) for r in rules]
        # 修改逻辑/原因（2026-09-12）：存量巡检/报表模式——逐条标注 path_kind 与
        # eligible（是否具备库级资格），用于找出"配置了但永远不生效"的文件级授权。
        # 默认关闭：逐条资格探针是 RPC，列表页不该为此变慢（用 annotate_eligibility=true 显式开启）。
        if str(request.GET.get('annotate_eligibility', '')).strip().lower() in (
                '1', 'true', 'yes', 'on'):
            kind_cache = {}
            eligibility_cache = {}
            annotated = []
            for rule, item in zip(rules, serialized):
                if rule.path not in kind_cache:
                    kind_cache[rule.path] = probes.path_kind(repo_id, rule.path)
                key = (rule.subject_type, rule.subject)
                if key not in eligibility_cache:
                    eligibility_cache[key] = probes.subject_eligible(
                        repo_id, rule.subject_type, rule.subject)
                annotated.append(granularity.annotate(
                    item, kind_cache[rule.path], eligibility_cache[key]))
            serialized = annotated

        return Response({
            'repo_id': repo_id,
            'total': total,
            'page': page,
            'per_page': per_page,
            'rules': serialized,
        })

    def post(self, request, repo_id):
        if not is_enabled('CF_ENABLE_DIR_ACL'):
            return _feature_off()

        from cloudfile_ext.acl.models import DirACL

        path = resolver.normalize_path(request.data.get('path', '/'))
        subject_type = request.data.get('subject_type', '')
        subject = request.data.get('subject', '')
        permission = request.data.get('permission', '')
        inherit = request.data.get('inherit', True)

        if subject_type not in VALID_SUBJECT_TYPES:
            return api_error(status.HTTP_400_BAD_REQUEST,
                             '主体类型不合法。')
        if not subject:
            return api_error(status.HTTP_400_BAD_REQUEST, '主体不合法。')
        if permission not in VALID_PERMISSIONS:
            return api_error(status.HTTP_400_BAD_REQUEST,
                             '权限值不合法。')

        # 修改逻辑/原因（2026-09-23 口径说明）：这一行（以及 acl/apis.py 的同名
        # 校验）就是「外部资料源配不了目录级 ACL」的成因——合成 repo_id 不是真实
        # 库，必然 404。判定路径是通的（外部源把合成 id 交给权限钩子，钩子只查
        # cf_dir_acl），所以 v1 的授权只到源级 grant。
        # 放行方案（三项加法式改动，需容器 E2E 证明后再做，清单见
        # docs/features/external-sources.md「权限」）：① 本端点改判「真实库 or
        # 已启用的外部源」；② probes.path_kind 对外部源改问 provider；
        # ③ probes.subject_eligible 对外部源改判「已有源级 grant」。
        # 不要在没有 E2E 的情况下直接放行：ACL 模块有「逻辑不可测 → 同一缺陷
        # 发布两次」的前例（FEATURES 第 71 项）。
        if not seafile_api.get_repo(repo_id):
            return api_error(status.HTTP_404_NOT_FOUND, '库不存在。')

        # As in the owner-facing endpoint: store the identity enforcement
        # compares, not what was typed. See cloudfile_ext/acl/subjects.py.
        try:
            subject = subjects.resolve(subject_type, subject)
        except subjects.UnknownSubject as e:
            return api_error(status.HTTP_400_BAD_REQUEST,
                             'subject not found: %s' % e)

        # 修改逻辑/原因（2026-09-12 粒度策略）：管理通道同样执行"授权只到目录、文件仅 deny"
        # 与资格校验——空头规则大多正是管理端写入的；需要预置时传 allow_ineffective=true。
        kind = probes.path_kind(repo_id, path)
        message = granularity.check_grant(kind, permission)
        if message:
            return api_error(status.HTTP_400_BAD_REQUEST, message)
        if str(request.data.get('allow_ineffective', '')).strip().lower() not in (
                '1', 'true', 'yes', 'on'):
            eligible = probes.subject_eligible(repo_id, subject_type, subject)
            message = granularity.check_eligibility(eligible, subject_type)
            if message:
                return api_error(status.HTTP_400_BAD_REQUEST, message)

        try:
            rule = DirACL.objects.set_rule(
                repo_id, path, subject_type, subject, permission,
                inherit=bool(inherit))
        except Exception as e:
            logger.error(e)
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR,
                             '服务器内部错误。')

        service.invalidate_repo(repo_id)
        return Response(_serialize(rule))

    def delete(self, request, repo_id):
        if not is_enabled('CF_ENABLE_DIR_ACL'):
            return _feature_off()

        from cloudfile_ext.acl.models import DirACL

        path = request.GET.get('path')
        subject_type = request.GET.get('subject_type', '')
        subject = request.GET.get('subject', '')

        try:
            if path is None:
                # Clearing a whole library's ACL is the "owner has left and
                # nobody can get in" escape hatch.
                DirACL.objects.filter(repo_id=repo_id).delete()
            else:
                if subject_type not in VALID_SUBJECT_TYPES or not subject:
                    return api_error(status.HTTP_400_BAD_REQUEST,
                                     '主体类型或主体不合法。')
                try:
                    subject = subjects.resolve(subject_type, subject)
                except subjects.UnknownSubject as e:
                    return api_error(status.HTTP_400_BAD_REQUEST,
                                     'subject not found: %s' % e)
                deleted, _ = DirACL.objects.delete_rule(
                    repo_id, resolver.normalize_path(path), subject_type,
                    subject)
                if not deleted:
                    return api_error(status.HTTP_404_NOT_FOUND,
                                     '规则不存在。')
        except Exception as e:
            logger.error(e)
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR,
                             '服务器内部错误。')

        service.invalidate_repo(repo_id)
        return Response({'success': True})


class AdminDirACLMigrateView(APIView):
    """Re-point a library's ACL rules after a rename/move (admin channel).

    修改逻辑/原因（2026-09-12 即时迁移）：规则按 path 存储，改名/移动不会自动搬运。
    周期任务 acl-path-migration 通过 seafevents Activity 兜底修复，但那是"已提交历史"，
    存在一个周期的滞后窗口（默认 ≤60s）。门户发起的改名/移动是**已知事件**，eap 在操作成功后
    直接调用本端点，把该路径下的规则即时迁移到新路径；WebDAV/桌面客户端等其它入口仍由周期任务覆盖。

    幂等：以 (old_path -> new_path) 重写，重复调用不会产生额外变更。
    """

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser,)
    throttle_classes = (UserRateThrottle,)

    def post(self, request, repo_id):
        if not is_enabled('CF_ENABLE_DIR_ACL'):
            return _feature_off()

        from cloudfile_ext.acl import migration

        old_path = request.data.get('old_path')
        new_path = request.data.get('new_path')
        if not old_path or not new_path:
            return api_error(status.HTTP_400_BAD_REQUEST,
                             '必须提供 old_path 与 new_path。')

        old_path = resolver.normalize_path(old_path)
        new_path = resolver.normalize_path(new_path)
        if old_path == new_path:
            return Response({'migrated': 0})

        try:
            migrated = migration.migrate_path(repo_id, old_path, new_path)
        except Exception as e:
            logger.error(e)
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR,
                             '服务器内部错误。')

        service.invalidate_repo(repo_id)
        return Response({'migrated': migrated})


class AdminDirAdminView(APIView):
    """List or clear a library's directory-admin grants, as an administrator.

    The recovery counterpart to AdminDirACLView: a library whose owner left
    still needs somebody able to inspect and revoke delegated admin grants
    (acl-semantics.md 7.2).
    """

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser,)
    throttle_classes = (UserRateThrottle,)

    def get(self, request, repo_id):
        if not is_enabled('CF_ENABLE_DIR_ACL'):
            return _feature_off()

        from cloudfile_ext.acl.models import DirAdmin

        try:
            page = int(request.GET.get('page', '1'))
            per_page = min(int(request.GET.get('per_page', '100')),
                           MAX_RULES_PER_PAGE)
        except ValueError:
            return api_error(status.HTTP_400_BAD_REQUEST,
                             'page 或 per_page 不合法。')
        if page < 1 or per_page < 1:
            return api_error(status.HTTP_400_BAD_REQUEST,
                             'page 或 per_page 不合法。')

        qs = DirAdmin.objects.filter(repo_id=repo_id).order_by('path', 'id')
        total = qs.count()
        start = (page - 1) * per_page
        grants = qs[start:start + per_page]

        return Response({
            'repo_id': repo_id,
            'total': total,
            'page': page,
            'per_page': per_page,
            'grants': [_serialize_admin(g) for g in grants],
        })

    def delete(self, request, repo_id):
        if not is_enabled('CF_ENABLE_DIR_ACL'):
            return _feature_off()

        from cloudfile_ext.acl.models import DirAdmin

        path = request.GET.get('path')
        subject_type = request.GET.get('subject_type', '')
        subject = request.GET.get('subject', '')

        try:
            if path is None:
                # Clearing a whole library's delegated grants is the "owner
                # has left" escape hatch for the manage dimension.
                DirAdmin.objects.filter(repo_id=repo_id).delete()
            else:
                if subject_type not in VALID_SUBJECT_TYPES or not subject:
                    return api_error(status.HTTP_400_BAD_REQUEST,
                                     '主体类型或主体不合法。')
                try:
                    subject = subjects.resolve(subject_type, subject)
                except subjects.UnknownSubject as e:
                    return api_error(status.HTTP_400_BAD_REQUEST,
                                     'subject not found: %s' % e)
                deleted, _ = DirAdmin.objects.delete_rule(
                    repo_id, resolver.normalize_path(path), subject_type,
                    subject)
                if not deleted:
                    return api_error(status.HTTP_404_NOT_FOUND,
                                     '委派记录不存在。')
        except Exception as e:
            logger.error(e)
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR,
                             '服务器内部错误。')

        service.invalidate_repo(repo_id)
        return Response({'success': True})
