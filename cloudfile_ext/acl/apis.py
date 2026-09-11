# -*- coding: utf-8 -*-
"""Directory ACL management endpoints.

Managing ACL on a directory or file is itself a privileged operation: only a
library admin or a covering directory-level admin (`PermissionService.
can_manage`) may change it. Requiring plain `rw` would let anyone a folder was
shared with re-share it more widely.
"""

import logging

from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from seaserv import seafile_api

from seahub.api2.authentication import TokenAuthentication
from seahub.api2.throttling import UserRateThrottle
from seahub.api2.utils import api_error
from seahub.constants import PERMISSION_READ_WRITE

from cloudfile_ext.features import is_enabled
from cloudfile_ext import identity
from cloudfile_ext.acl import granularity, probes, resolver, service, subjects
from cloudfile_ext.acl.models import DirACL
from cloudfile_ext.permissions import PermissionService

logger = logging.getLogger(__name__)

VALID_PERMISSIONS = tuple(resolver.PERMISSION_ORDER)
VALID_SUBJECT_TYPES = (resolver.SUBJECT_USER, resolver.SUBJECT_DEPT,
                       resolver.SUBJECT_GROUP)


def _feature_off():
    return api_error(status.HTTP_404_NOT_FOUND, 'Directory ACL is not enabled.')


def _truthy(value):
    """Query/body boolean that also accepts the strings a client sends."""
    if isinstance(value, bool):
        return value
    return str(value or '').strip().lower() in ('1', 'true', 'yes', 'on')


def _check_can_manage(request, repo_id, path):
    """Return an error Response, or None when the caller may manage ACL here.

    Library adminship or a covering directory-level admin grant is required
    (``PermissionService.can_manage``), so a user a folder was merely shared
    with cannot re-share it more widely, while a delegated directory admin can
    manage within their scope.

    The permission check deliberately uses the *native* repo permission rather
    than check_folder_permission: the latter now applies the directory ACL, so
    an admin who wrote a restrictive rule covering themselves would be locked
    out of the very endpoint needed to remove it.
    """
    repo = seafile_api.get_repo(repo_id)
    if not repo:
        return api_error(status.HTTP_404_NOT_FOUND, 'Library not found.')

    # Rules may target a directory or a file (acl-semantics.md 4.3); the path
    # must simply exist.
    if (not seafile_api.get_dir_id_by_path(repo_id, path)
            and not seafile_api.get_file_id_by_path(repo_id, path)):
        return api_error(status.HTTP_404_NOT_FOUND, 'Path not found.')

    username = request.user.username
    if seafile_api.check_permission(repo_id, username) != PERMISSION_READ_WRITE:
        return api_error(status.HTTP_403_FORBIDDEN, 'Permission denied.')

    if not PermissionService.can_manage(username, repo_id, path):
        return api_error(status.HTTP_403_FORBIDDEN,
                         'Only a library admin can manage directory ACL.')
    return None


def _serialize(rule):
    return {
        'repo_id': rule.repo_id,
        'path': rule.path,
        'subject_type': rule.subject_type,
        'subject': rule.subject,
        'external_subject_id': _external_subject_id(rule),
        'permission': rule.permission,
        'inherit': bool(rule.inherit),
        'mtime': rule.mtime,
    }


def _external_subject_id(rule):
    """The external id the directory knows this subject by, or None.

    Rule subjects are stored as Seafile identities (what enforcement compares
    against -- cf_dir_acl.subject is `xxx@auth.local` on any SSO deployment).
    An eap-facing client needs the reverse: the employee number / contact email
    / org_group id / role id its own directory understands. identity.login_of
    is that exact reverse mapping for users.

    dept/group subjects are stored as Seafile group ids; the reverse mapping
    is the SSO group map (``583 -> '7'``), installed on the baseline as the
    group-id resolver. When no reverse resolver is installed, or the group id
    is not mapped (a hand-created group / role keyed differently), the group
    id passes through unchanged so a client never reads a blank.
    """
    if rule.subject_type == resolver.SUBJECT_USER:
        try:
            return identity.login_of(rule.subject)
        except Exception:
            logger.warning('login_of(%s) failed', rule.subject, exc_info=True)
            return None

    # dept / group: translate the stored Seafile group id back to the
    # directory's external id, falling back to the raw group id.
    reverse_resolver = identity.default_group_id_resolver()
    if reverse_resolver:
        try:
            mapped = reverse_resolver(rule.subject)
        except Exception:
            logger.warning('group-id reverse lookup for %s failed',
                           rule.subject, exc_info=True)
            mapped = None
        if mapped is not None:
            return mapped
    return rule.subject


class DirACLView(APIView):
    """List, set and delete ACL rules on one folder."""

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    def get(self, request, repo_id):
        if not is_enabled('CF_ENABLE_DIR_ACL'):
            return _feature_off()

        path = resolver.normalize_path(request.GET.get('path', '/'))
        error = _check_can_manage(request, repo_id, path)
        if error:
            return error

        rules = list(DirACL.objects.filter(
            repo_id=repo_id, path_hash=resolver.path_hash(path)))
        # 修改原因（2026-09-12）：列表带上 path_kind/eligible/guidance，
        # 让"配置了但永远不生效"的规则在管理面可见（此前只能靠直连数据库发现）。
        kind = probes.path_kind(repo_id, path)
        eligibility_cache = {}
        serialized = []
        for rule in rules:
            key = (rule.subject_type, rule.subject)
            if key not in eligibility_cache:
                eligibility_cache[key] = probes.subject_eligible(
                    repo_id, rule.subject_type, rule.subject)
            serialized.append(granularity.annotate(
                _serialize(rule), kind, eligibility_cache[key]))
        return Response({'path': path, 'rules': serialized})

    def post(self, request, repo_id):
        if not is_enabled('CF_ENABLE_DIR_ACL'):
            return _feature_off()

        path = resolver.normalize_path(request.data.get('path', '/'))
        subject_type = request.data.get('subject_type', '')
        subject = request.data.get('subject', '')
        permission = request.data.get('permission', '')
        inherit = request.data.get('inherit', True)

        if subject_type not in VALID_SUBJECT_TYPES:
            return api_error(status.HTTP_400_BAD_REQUEST,
                             'subject_type invalid.')
        if not subject:
            return api_error(status.HTTP_400_BAD_REQUEST, 'subject invalid.')
        if permission not in VALID_PERMISSIONS:
            return api_error(status.HTTP_400_BAD_REQUEST,
                             'permission invalid.')

        error = _check_can_manage(request, repo_id, path)
        if error:
            return error

        # Store the identity enforcement compares against, not what was typed.
        # Since Seafile 14 those differ: a rule saved against an email never
        # matches, and fails open in silence. See cloudfile_ext/acl/subjects.py.
        try:
            subject = subjects.resolve(subject_type, subject)
        except subjects.UnknownSubject as e:
            return api_error(status.HTTP_400_BAD_REQUEST,
                             'subject not found: %s' % e)

        # 修改逻辑/原因（2026-09-12 粒度策略）：授权粒度=目录/库根；文件路径只接受 deny。
        # 写内容类操作在上游按父目录判定（file.py 的 parent_dir），文件级 r/rw 会在管理界面
        # "配置成功"却在写路径静默失效——正是我们排查过的那类工单；因此在写入时直接拒绝并给出引导。
        kind = probes.path_kind(repo_id, path)
        message = granularity.check_grant(kind, permission)
        if message:
            return api_error(status.HTTP_400_BAD_REQUEST, message)

        # 资格校验：路径规则只能在库级权限内细化，不能凭空造权限
        # （resolver.resolve 在 native 为 None 时恒返回 None）。默认拒绝"空头支票"，
        # 需要预置规则时可显式传 allow_ineffective=true 绕过。
        if not _truthy(request.data.get('allow_ineffective')):
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
                             'Internal Server Error')

        service.invalidate_repo(repo_id)
        return Response(_serialize(rule))

    def delete(self, request, repo_id):
        if not is_enabled('CF_ENABLE_DIR_ACL'):
            return _feature_off()

        path = resolver.normalize_path(request.GET.get('path', '/'))
        subject_type = request.GET.get('subject_type', '')
        subject = request.GET.get('subject', '')

        if subject_type not in VALID_SUBJECT_TYPES or not subject:
            return api_error(status.HTTP_400_BAD_REQUEST,
                             'subject_type or subject invalid.')

        error = _check_can_manage(request, repo_id, path)
        if error:
            return error

        # Same resolution as POST, or a rule created by email could not be
        # deleted by email -- the delete would report success having matched
        # nothing, which is the same silent-failure shape in reverse.
        try:
            subject = subjects.resolve(subject_type, subject)
        except subjects.UnknownSubject as e:
            return api_error(status.HTTP_400_BAD_REQUEST,
                             'subject not found: %s' % e)

        try:
            deleted, _ = DirACL.objects.delete_rule(
                repo_id, path, subject_type, subject)
            if not deleted:
                return api_error(status.HTTP_404_NOT_FOUND, 'rule not found.')
        except Exception as e:
            logger.error(e)
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'Internal Server Error')

        service.invalidate_repo(repo_id)
        return Response({'success': True})


class DirACLEffectiveView(APIView):
    """Show the effective permission a user has on a path, and why.

    Exists because inheritance across levels and subject types is hard to
    reason about from the raw rule list; support needs to be able to answer
    "why can B not open this folder" without reading the table by hand.
    """

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    def get(self, request, repo_id):
        if not is_enabled('CF_ENABLE_DIR_ACL'):
            return _feature_off()

        path = resolver.normalize_path(request.GET.get('path', '/'))
        # Checking another user's effective permission is an admin-grade
        # disclosure, so it is gated the same way rule management is.
        target = request.GET.get('user', '') or request.user.username

        # This endpoint answers "why can Bob not open that folder", and whoever
        # is asking knows Bob's email, not his opaque id. Resolving here also
        # keeps the answer honest: without it, an email would silently compute
        # the permissions of a user that does not exist and report no access --
        # which looks exactly like a correctly restrictive rule.
        if target != request.user.username:
            try:
                target = subjects.resolve(resolver.SUBJECT_USER, target)
            except subjects.UnknownSubject as e:
                return api_error(status.HTTP_400_BAD_REQUEST,
                                 'user not found: %s' % e)

        if target != request.user.username:
            error = _check_can_manage(request, repo_id, path)
            if error:
                return error

        native = seafile_api.check_permission(repo_id, target)
        effective = PermissionService.effective_perm(target, repo_id, path,
                                                     native)

        return Response({
            'path': path,
            'user': target,
            'native_permission': native,
            'effective_permission': effective,
            'can_manage': PermissionService.can_manage(target, repo_id, path),
            'levels': resolver.ancestors(path),
        })


def _serialize_admin(rule):
    return {
        'repo_id': rule.repo_id,
        'path': rule.path,
        'subject_type': rule.subject_type,
        'subject': rule.subject,
        'external_subject_id': _external_subject_id(rule),
        'inherit': bool(rule.inherit),
        'mtime': rule.mtime,
    }


class DirAdminView(APIView):
    """List, grant and revoke directory-level admin (delegated manage).

    A grant covers the directory it is set on and, with inherit, everything
    below it (acl-semantics.md 7). Who may manage here is decided by the same
    ``PermissionService.can_manage`` the content endpoints use, so a directory
    admin can delegate further down but never outside their own scope.
    """

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    def get(self, request, repo_id):
        if not is_enabled('CF_ENABLE_DIR_ACL'):
            return _feature_off()

        path = resolver.normalize_path(request.GET.get('path', '/'))
        error = _check_can_manage(request, repo_id, path)
        if error:
            return error

        from cloudfile_ext.acl.models import DirAdmin
        grants = DirAdmin.objects.filter(
            repo_id=repo_id, path_hash=resolver.path_hash(path))
        return Response({'path': path,
                         'grants': [_serialize_admin(g) for g in grants]})

    def post(self, request, repo_id):
        if not is_enabled('CF_ENABLE_DIR_ACL'):
            return _feature_off()

        path = resolver.normalize_path(request.data.get('path', '/'))
        subject_type = request.data.get('subject_type', '')
        subject = request.data.get('subject', '')
        inherit = request.data.get('inherit', True)

        if subject_type not in VALID_SUBJECT_TYPES:
            return api_error(status.HTTP_400_BAD_REQUEST,
                             'subject_type invalid.')
        if not subject:
            return api_error(status.HTTP_400_BAD_REQUEST, 'subject invalid.')

        error = _check_can_manage(request, repo_id, path)
        if error:
            return error

        try:
            subject = subjects.resolve(subject_type, subject)
        except subjects.UnknownSubject as e:
            return api_error(status.HTTP_400_BAD_REQUEST,
                             'subject not found: %s' % e)

        try:
            from cloudfile_ext.acl.models import DirAdmin
            grant = DirAdmin.objects.set_rule(
                repo_id, path, subject_type, subject, inherit=bool(inherit))
        except Exception as e:
            logger.error(e)
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'Internal Server Error')

        service.invalidate_repo(repo_id)
        return Response(_serialize_admin(grant))

    def delete(self, request, repo_id):
        if not is_enabled('CF_ENABLE_DIR_ACL'):
            return _feature_off()

        path = resolver.normalize_path(request.GET.get('path', '/'))
        subject_type = request.GET.get('subject_type', '')
        subject = request.GET.get('subject', '')

        if subject_type not in VALID_SUBJECT_TYPES or not subject:
            return api_error(status.HTTP_400_BAD_REQUEST,
                             'subject_type or subject invalid.')

        error = _check_can_manage(request, repo_id, path)
        if error:
            return error

        try:
            subject = subjects.resolve(subject_type, subject)
        except subjects.UnknownSubject as e:
            return api_error(status.HTTP_400_BAD_REQUEST,
                             'subject not found: %s' % e)

        try:
            from cloudfile_ext.acl.models import DirAdmin
            deleted, _ = DirAdmin.objects.delete_rule(
                repo_id, path, subject_type, subject)
            if not deleted:
                return api_error(status.HTTP_404_NOT_FOUND, 'grant not found.')
        except Exception as e:
            logger.error(e)
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'Internal Server Error')

        service.invalidate_repo(repo_id)
        return Response({'success': True})
