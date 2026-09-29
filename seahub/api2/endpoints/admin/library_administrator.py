"""Library administrators are management grants, independent of content shares."""
import logging

from django.db import transaction
from seaserv import ccnet_api, seafile_api
from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from seahub.api2.authentication import TokenAuthentication
from seahub.api2.throttling import UserRateThrottle
from seahub.api2.utils import api_error
from seahub.base.accounts import AuthBackend, User
from seahub.auth.utils import get_virtual_id_by_email
from seahub.profile.models import Profile
from seahub.share.models import ExtraSharePermission, ExtraGroupsSharePermission
from seahub.share.utils import (is_repo_admin, share_dir_to_user, share_dir_to_group,
                                update_user_dir_permission, update_group_dir_permission)
from seahub.utils import is_valid_email, send_perm_audit_msg

logger = logging.getLogger(__name__)


def _org_repo_owner(repo_id):
    lookup = getattr(seafile_api, 'get_org_repo_owner', None)
    return lookup(repo_id) if lookup else None


class AdminLibraryAdministrator(APIView):
    # Keep the original endpoint's auto-read behavior for existing extensions.
    # New clients that need a one-call read-write grant use the explicit subclass
    # registered at /administrator-with-access/.
    admin_content_permission = 'r'
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    def _authorize(self, request, repo_id):
        repo = seafile_api.get_repo(repo_id)
        if not repo:
            return api_error(status.HTTP_404_NOT_FOUND, 'Library not found.')
        if getattr(repo, 'is_virtual', False):
            return api_error(status.HTTP_403_FORBIDDEN, 'Virtual library cannot be managed.')
        user = request.user
        if user.is_staff and user.admin_permissions.can_manage_library():
            return None
        if not is_repo_admin(user.username, repo_id, strict=True):
            return api_error(status.HTTP_403_FORBIDDEN, 'Permission denied.')
        return None

    @staticmethod
    def _target(kind, subject):
        if kind == 'user' and isinstance(subject, str) and is_valid_email(subject):
            return ExtraSharePermission, subject
        if (kind == 'group' and isinstance(subject, str) and subject.isascii()
                and subject.isdecimal() and 0 < int(subject) <= 2147483647):
            return ExtraGroupsSharePermission, int(subject)
        return None, None

    @staticmethod
    def _response(repo_id, kind, subject, action):
        result = Response({'repo_id': repo_id, 'subject_type': kind,
                           'subject': str(subject), action: True})
        result['Cache-Control'] = 'no-store'
        return result

    @staticmethod
    def _effective(repo_id, kind, subject, is_org, minimum_permission='r'):
        if kind == 'user':
            try:
                user = User.objects.get(email=subject)
            except User.DoesNotExist:
                return False
            permission = seafile_api.check_permission(repo_id, user.username)
            return bool(user.is_active and permission in ('r', 'rw') and
                        (minimum_permission == 'r' or permission == 'rw'))
        if not ccnet_api.get_group(subject):
            return False
        share = seafile_api.get_group_shared_repo_by_path(repo_id, None, subject, is_org)
        return bool(share and share.permission in ('r', 'rw') and
                    (minimum_permission == 'r' or share.permission == 'rw'))

    @staticmethod
    def _group_name(group_id):
        group = ccnet_api.get_group(group_id)
        return group.group_name if group else None

    @staticmethod
    def _direct_share(repo_id, kind, subject, is_org):
        if kind == 'user':
            return seafile_api.get_shared_repo_by_path(repo_id, None, subject, is_org)
        return seafile_api.get_group_shared_repo_by_path(repo_id, None, subject, is_org)

    @classmethod
    def _restore_auto_access(cls, repo_id, kind, subject, granted_permission,
                             previous_permission):
        org_owner = _org_repo_owner(repo_id)
        is_org = bool(org_owner)
        share = cls._direct_share(repo_id, kind, subject, is_org)
        # An owner may have changed the share after the automatic grant. Keep that
        # independent change instead of undoing a permission that no longer matches.
        if not share or share.permission != granted_permission:
            return
        owner = (org_owner if is_org
                 else seafile_api.get_repo_owner(repo_id))
        if not owner:
            raise RuntimeError('Library owner is unavailable')
        if previous_permission:
            if previous_permission != 'r':
                raise RuntimeError('Unsupported previous library permission')
            org_id = seafile_api.get_org_id_by_repo_id(repo_id) if is_org else None
            if kind == 'user':
                update_user_dir_permission(repo_id, '/', owner, subject, previous_permission,
                                           org_id=org_id)
            else:
                update_group_dir_permission(repo_id, '/', owner, subject, previous_permission,
                                            org_id=org_id)
            return
        if is_org:
            org_id = seafile_api.get_org_id_by_repo_id(repo_id)
            if kind == 'user':
                seafile_api.org_remove_share(org_id, repo_id, owner, subject)
            else:
                seafile_api.del_org_group_repo(repo_id, org_id, subject)
        elif kind == 'user':
            seafile_api.remove_share(repo_id, owner, subject)
        else:
            seafile_api.unset_group_repo(repo_id, subject, owner)

    def get(self, request, repo_id):
        if request.GET:
            return api_error(status.HTTP_400_BAD_REQUEST, 'Query parameters are not supported.')
        try:
            denied = self._authorize(request, repo_id)
            if denied is not None:
                return denied
            users = ExtraSharePermission.objects.get_admin_users_by_repo(repo_id)
            groups = ExtraGroupsSharePermission.objects.get_admin_groups_by_repo(repo_id)
            is_org = bool(_org_repo_owner(repo_id))
            result = Response({'repo_id': repo_id, 'administrators': [
                *({'subject_type': 'user', 'subject': Profile.objects.get_contact_email_by_user(user),
                   'effective': self._effective(repo_id, 'user', user, is_org,
                                                self.admin_content_permission)}
                  for user in sorted(set(users))),
                *({'subject_type': 'group', 'subject': str(group),
                   'display_name': self._group_name(group),
                   'effective': self._effective(repo_id, 'group', group, is_org,
                                                self.admin_content_permission)}
                  for group in sorted(set(groups))),
            ]})
            result['Cache-Control'] = 'no-store'
            return result
        except Exception:
            logger.exception('Library administrator listing failed')
            return api_error(status.HTTP_503_SERVICE_UNAVAILABLE, 'Administrator service unavailable.')

    def post(self, request, repo_id):
        if request.GET or set(request.data) != {'subject_type', 'subject'}:
            return api_error(status.HTTP_400_BAD_REQUEST, 'A single administrator target is required.')
        kind, subject = request.data['subject_type'], request.data['subject']
        store, target = self._target(kind, subject)
        if store is None:
            return api_error(status.HTTP_400_BAD_REQUEST, 'Invalid administrator target.')
        try:
            denied = self._authorize(request, repo_id)
            if denied is not None:
                return denied
            if kind == 'user':
                target = get_virtual_id_by_email(target)
            # The legacy API only auto-grants read. The explicit one-call API
            # overrides this to rw and upgrades a prior direct read-only share.
            required_permission = self.admin_content_permission
            access_missing = False
            direct_share = None
            org_owner = _org_repo_owner(repo_id)
            is_org = bool(org_owner)
            if kind == 'user':
                try:
                    user = User.objects.get(email=target)
                except User.DoesNotExist:
                    # LDAP users may be visible before their first login;
                    # import their native account before evaluating the grant.
                    try:
                        user = AuthBackend().get_user_with_import(target)
                    except User.DoesNotExist:
                        return api_error(status.HTTP_404_NOT_FOUND, 'User not found.')
                if not user.is_active:
                    return api_error(status.HTTP_409_CONFLICT, 'User is inactive.')
                # An inherited group share is not a durable grant for this user.
                direct_share = self._direct_share(repo_id, kind, user.username, is_org)
                access_missing = direct_share is None
                owner = (org_owner if is_org
                         else seafile_api.get_repo_owner(repo_id))
                if user.username == owner:
                    access_missing = False
                target = user.username
            else:
                if not ccnet_api.get_group(target):
                    return api_error(status.HTTP_404_NOT_FOUND, 'Group not found.')
                direct_share = self._direct_share(repo_id, kind, target, is_org)
                access_missing = direct_share is None
            access_needs_upgrade = bool(required_permission == 'rw' and direct_share and
                                        direct_share.permission == 'r')
            if direct_share and direct_share.permission not in ('r', 'rw'):
                return api_error(status.HTTP_409_CONFLICT,
                                 'Existing library permission cannot be upgraded automatically.')
            access_needs_change = access_missing or access_needs_upgrade
            previous_permission = direct_share.permission if direct_share else ''
            native_access_changed = False
            with transaction.atomic():
                try:
                    if access_needs_change:
                        owner = (org_owner if is_org
                                 else seafile_api.get_repo_owner(repo_id))
                        if not owner:
                            return api_error(status.HTTP_503_SERVICE_UNAVAILABLE, 'Library owner is unavailable.')
                        org_id = seafile_api.get_org_id_by_repo_id(repo_id) if is_org else None
                        # RPC may fail after applying the share; compensation reads
                        # back the exact state before restoring or removing it.
                        native_access_changed = True
                        if access_missing and kind == 'user':
                            share_dir_to_user(seafile_api.get_repo(repo_id), '/', owner,
                                              request.user.username, target, required_permission,
                                              org_id=org_id)
                        elif access_missing:
                            share_dir_to_group(seafile_api.get_repo(repo_id), '/', owner,
                                               request.user.username, target, required_permission,
                                               org_id=org_id)
                        elif kind == 'user':
                            update_user_dir_permission(repo_id, '/', owner, target,
                                                       required_permission, org_id=org_id)
                        else:
                            update_group_dir_permission(repo_id, '/', owner, target,
                                                        required_permission, org_id=org_id)
                        if not self._effective(repo_id, kind, target, is_org,
                                               required_permission):
                            raise RuntimeError('Required native library access did not become effective')
                    lookup = {'repo_id': repo_id, 'share_to' if kind == 'user' else 'group_id': target}
                    marker, created = store.objects.get_or_create(
                        **lookup, defaults={
                            'permission': 'admin',
                            'auto_granted_access': access_needs_change,
                            'auto_granted_permission': required_permission if access_needs_change else '',
                            'auto_grant_previous_permission': previous_permission if access_needs_change else '',
                        })
                    changed = created or marker.permission != 'admin'
                    fields = []
                    if not created:
                        if changed:
                            marker.permission = 'admin'
                            fields.append('permission')
                        if access_needs_change and marker.auto_granted_access is not True:
                            marker.auto_granted_access = True
                            marker.auto_granted_permission = required_permission
                            marker.auto_grant_previous_permission = previous_permission
                            fields.extend(['auto_granted_access', 'auto_granted_permission',
                                           'auto_grant_previous_permission'])
                        elif access_needs_change and marker.auto_granted_access is True:
                            if marker.auto_granted_permission != required_permission:
                                marker.auto_granted_permission = required_permission
                                fields.append('auto_granted_permission')
                        if fields:
                            marker.save(update_fields=fields)
                    if changed or access_needs_change:
                        send_perm_audit_msg('add-repo-perm', request.user.username, str(target),
                                            repo_id, '/', 'grant-admin')
                except Exception:
                    if native_access_changed:
                        try:
                            self._restore_auto_access(repo_id, kind, target, required_permission,
                                                      previous_permission)
                        except Exception:
                            logger.exception('Failed to compensate library administrator native share')
                    raise
            # Keep the public API identity stable: Seafile stores a virtual ID,
            # while callers submitted the contact email and validate its echo.
            return self._response(repo_id, kind, subject, 'granted')
        except Exception:
            logger.exception('Library administrator grant failed')
            return api_error(status.HTTP_503_SERVICE_UNAVAILABLE, 'Administrator service unavailable.')


    def delete(self, request, repo_id):
        if set(request.GET) != {'subject_type', 'subject'} or any(len(request.GET.getlist(k)) != 1 for k in request.GET):
            return api_error(status.HTTP_400_BAD_REQUEST, 'Invalid administrator target.')
        kind, subject = request.GET['subject_type'], request.GET['subject']
        store, target = self._target(kind, subject)
        if store is None:
            return api_error(status.HTTP_400_BAD_REQUEST, 'Invalid administrator target.')
        try:
            denied = self._authorize(request, repo_id)
            if denied is not None:
                return denied
            if kind == 'user':
                target = get_virtual_id_by_email(target)
            with transaction.atomic():
                lookup = {'repo_id': repo_id, 'share_to' if kind == 'user' else 'group_id': target}
                marker = store.objects.select_for_update().filter(**lookup).first()
                if marker and marker.auto_granted_access is True:
                    self._restore_auto_access(
                        repo_id, kind, target,
                        marker.auto_granted_permission or 'r',
                        marker.auto_grant_previous_permission or '')
                store.objects.delete_share_permission(repo_id, target)
                send_perm_audit_msg('modify-repo-perm', request.user.username, str(target),
                                    repo_id, '/', 'revoke-admin')
            return self._response(repo_id, kind, subject, 'removed')
        except Exception:
            logger.exception('Library administrator removal failed')
            return api_error(status.HTTP_503_SERVICE_UNAVAILABLE, 'Administrator service unavailable.')


class AdminLibraryAdministratorWithAccess(AdminLibraryAdministrator):
    """One-call administrator grant that guarantees direct read-write access."""
    admin_content_permission = 'rw'
