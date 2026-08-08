# -*- coding: utf-8 -*-
"""Authenticated file-action and local-Agent endpoints."""

import os
import tempfile

from django.shortcuts import render
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import IsAdminUser, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from seaserv import seafile_api

from seahub.api2.authentication import TokenAuthentication
from seahub.api2.throttling import UserRateThrottle
from seahub.api2.utils import api_error
from seahub.auth.decorators import login_required
from seahub.utils import normalize_file_path
from seahub.utils.repo import parse_repo_perm
from seahub.views import check_folder_permission

from cloudfile_ext.features import is_enabled
from cloudfile_ext.file_actions import service


def _feature_off():
    return api_error(status.HTTP_404_NOT_FOUND, 'File actions are not enabled.')


def _get_file(request, repo_id, path, require_edit=False):
    if not path:
        return None, api_error(status.HTTP_400_BAD_REQUEST, 'path invalid.')
    path = normalize_file_path(path)
    if not seafile_api.get_repo(repo_id):
        return None, api_error(status.HTTP_404_NOT_FOUND, 'Library not found.')
    if not seafile_api.get_file_id_by_path(repo_id, path):
        return None, api_error(status.HTTP_404_NOT_FOUND, 'File not found.')
    permission = check_folder_permission(request, repo_id, path)
    if not permission:
        return None, api_error(status.HTTP_403_FORBIDDEN, 'Permission denied.')
    if require_edit and parse_repo_perm(permission).can_edit_on_web is False:
        return None, api_error(status.HTTP_403_FORBIDDEN, 'Edit permission required.')
    return path, None


def _get_file_for_admin(repo_id, path):
    """Locate a file without applying its owner's library permission rules."""
    if not path:
        return None, api_error(status.HTTP_400_BAD_REQUEST, 'path invalid.')
    path = normalize_file_path(path)
    if not seafile_api.get_repo(repo_id):
        return None, api_error(status.HTTP_404_NOT_FOUND, 'Library not found.')
    if not seafile_api.get_file_id_by_path(repo_id, path):
        return None, api_error(status.HTTP_404_NOT_FOUND, 'File not found.')
    return path, None


class _FileActionAPIView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)


class FileActionsView(_FileActionAPIView):
    """List relevant actions after a real, path-level permission check."""

    def get(self, request, repo_id):
        enabled = any(is_enabled(name) for name in (
            'CF_ENABLE_FILE_PREVIEW', 'CF_ENABLE_CHECKOUT', 'CF_ENABLE_LOCAL_APP',
        ))
        if not enabled:
            return _feature_off()
        path, error = _get_file(request, repo_id, request.GET.get('path', ''))
        if error:
            return error
        permission = check_folder_permission(request, repo_id, path)
        return Response({'repo_id': repo_id, 'path': path,
                         'actions': service.get_actions(
                             repo_id, path,
                             can_edit=parse_repo_perm(permission).can_edit_on_web)})


class LocalSessionView(_FileActionAPIView):
    """Issue a read-only hand-off for a Native Messaging Agent.

    Local write sessions are intentionally refused until the lock provider is
    registered in seafile-server.  That protects against a desktop client,
    WebDAV or an OnlyOffice callback bypassing a Hub-only checkout record.
    """

    def post(self, request, repo_id):
        if not is_enabled('CF_ENABLE_LOCAL_APP'):
            return _feature_off()
        mode = request.data.get('mode', 'local-view')
        path, error = _get_file(
            request, repo_id, request.data.get('path', ''),
            require_edit=mode == 'local-edit')
        if error:
            return error
        if mode == 'local-view':
            return Response(service.issue_local_view_session(
                repo_id, path, request.user.username), status=status.HTTP_201_CREATED)
        if mode != 'local-edit':
            return api_error(status.HTTP_400_BAD_REQUEST, 'mode invalid.')
        if not service.lock_provider_ready(repo_id, path):
            return api_error(status.HTTP_409_CONFLICT,
                             'Local editing requires the file-lock provider.')
        file_id = seafile_api.get_file_id_by_path(repo_id, path)
        result = service.issue_local_edit_session(
            repo_id, path, request.user.username, file_id)
        if not result.get('ok'):
            if result.get('reason') == 'locked':
                return Response(result, status=status.HTTP_423_LOCKED)
            return api_error(status.HTTP_503_SERVICE_UNAVAILABLE,
                             'File-lock service is unavailable.')
        return Response(result, status=status.HTTP_201_CREATED)


class AgentSessionClaimView(APIView):
    """Exchange one browser-visible ticket for agent-only file capabilities."""

    authentication_classes = ()
    permission_classes = ()
    throttle_classes = (UserRateThrottle,)

    def post(self, request):
        if not is_enabled('CF_ENABLE_LOCAL_APP'):
            return _feature_off()
        ticket = request.data.get('ticket', '')
        if not isinstance(ticket, str) or not ticket:
            return api_error(status.HTTP_400_BAD_REQUEST, 'ticket invalid.')
        origin = request.build_absolute_uri('/').rstrip('/')
        claimed = service.claim_agent_session(ticket, origin)
        if not claimed:
            return api_error(status.HTTP_410_GONE, 'Local session is unavailable or expired.')
        return Response(claimed)


class AgentContentView(APIView):
    """Commit one local-editor result using a one-file, fenced capability."""

    authentication_classes = ()
    permission_classes = ()
    parser_classes = (MultiPartParser, FormParser)

    def put(self, request, session_id):
        capability = request.headers.get('Authorization', '').removeprefix('Bearer ').strip()
        session = service.local_edit_session(session_id, capability)
        upload = request.FILES.get('file')
        if not session or not upload:
            return api_error(status.HTTP_410_GONE, 'Local editing session expired.')
        current = service._lock_rpc('cf_lock_status', {
            'repo_id': session['repo_id'], 'path': session['path'],
        })
        if not current.get('locked') or current.get('kind') != 'local-edit' \
                or current.get('owner') != session['username'] \
                or current.get('generation') != session['generation']:
            return api_error(status.HTTP_410_GONE, 'Local editing lease is no longer valid.')
        if seafile_api.get_file_id_by_path(session['repo_id'], session['path']) != session['base_file_id']:
            return api_error(status.HTTP_409_CONFLICT, 'The source file has changed.')

        parent, name = os.path.split(session['path'])
        tmp_name = None
        try:
            with tempfile.NamedTemporaryFile(prefix='cloudfile-agent-', delete=False) as tmp:
                tmp_name = tmp.name
                for chunk in upload.chunks():
                    tmp.write(chunk)
            seafile_api.post_file(session['repo_id'], tmp_name, parent or '/', name,
                                  session['username'])
        except Exception:
            return api_error(status.HTTP_503_SERVICE_UNAVAILABLE,
                             'Unable to save local editing result.')
        finally:
            if tmp_name:
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass

        service.release_checkout(session['repo_id'], session['path'],
                                 session['username'], session['generation'])
        service.consume_local_edit_session(session_id)
        return Response(status=status.HTTP_204_NO_CONTENT)


class AgentSessionHeartbeatView(APIView):
    """Renew only the claimed agent session's fenced local-edit lease."""

    authentication_classes = ()
    permission_classes = ()
    throttle_classes = (UserRateThrottle,)

    def patch(self, request, session_id):
        capability = request.headers.get('Authorization', '').removeprefix('Bearer ').strip()
        result = service.refresh_local_edit_session(session_id, capability)
        if not result:
            return api_error(status.HTTP_410_GONE, 'Local editing lease is no longer valid.')
        return Response(result)


class CheckoutView(_FileActionAPIView):
    """One checkout contract for a person and a third-party program.

    The endpoint validates the caller and source, then creates a lease through
    the C backend that the sync, WebDAV and HTTP write paths consult. It never
    creates a Hub-only advisory checkout record.
    """

    def post(self, request, repo_id):
        if not is_enabled('CF_ENABLE_CHECKOUT'):
            return _feature_off()
        path, error = _get_file(
            request, repo_id, request.data.get('path', ''), require_edit=True)
        if error:
            return error
        source = request.data.get('source', 'manual')
        if source not in ('manual', 'third-party'):
            return api_error(status.HTTP_400_BAD_REQUEST, 'source invalid.')
        if not service.lock_provider_ready(repo_id, path):
            return api_error(status.HTTP_409_CONFLICT,
                             'Checkout requires the server-side file-lock provider.')
        result = service.checkout(repo_id, path, request.user.username, source)
        if not result.get('ok'):
            if result.get('reason') == 'locked':
                return Response(result, status=status.HTTP_423_LOCKED)
            return api_error(status.HTTP_503_SERVICE_UNAVAILABLE,
                             'File-lock service is unavailable.')
        result['repo_id'] = repo_id
        result['path'] = path
        result['source'] = source
        return Response(result, status=status.HTTP_201_CREATED)

    def delete(self, request, repo_id):
        if not is_enabled('CF_ENABLE_CHECKOUT'):
            return _feature_off()
        path, error = _get_file(request, repo_id, request.data.get('path', ''))
        if error:
            return error
        generation = request.data.get('generation', '')
        if not generation:
            return api_error(status.HTTP_400_BAD_REQUEST, 'generation required.')
        result = service.release_checkout(
            repo_id, path, request.user.username, generation)
        if not result.get('ok'):
            if result.get('reason') == 'not_owner_or_stale':
                return api_error(status.HTTP_409_CONFLICT, 'Checkout is no longer active.')
            return api_error(status.HTTP_503_SERVICE_UNAVAILABLE,
                             'File-lock service is unavailable.')
        return Response(status=status.HTTP_204_NO_CONTENT)


class FileLockView(_FileActionAPIView):
    """CloudFile CE adapter for the native lock/unlock controls."""

    def get(self, request, repo_id):
        if not is_enabled('CF_ENABLE_FILE_LOCK'):
            return _feature_off()
        path, error = _get_file(request, repo_id, request.GET.get('path', ''))
        if error:
            return error
        result = service.lock_status(repo_id, path, request.user.username)
        if result.get('ok') is not True:
            return api_error(status.HTTP_503_SERVICE_UNAVAILABLE,
                             'File-lock service is unavailable.')
        return Response(result)

    def put(self, request, repo_id):
        if not is_enabled('CF_ENABLE_FILE_LOCK'):
            return _feature_off()
        path, error = _get_file(
            request, repo_id, request.data.get('path', ''), require_edit=True)
        if error:
            return error
        result = service.lock_file(repo_id, path, request.user.username)
        if not result.get('ok'):
            if result.get('reason') == 'locked':
                return Response(result, status=status.HTTP_423_LOCKED)
            return api_error(status.HTTP_503_SERVICE_UNAVAILABLE,
                             'File-lock service is unavailable.')
        return Response(result, status=status.HTTP_200_OK)

    def delete(self, request, repo_id):
        if not is_enabled('CF_ENABLE_FILE_LOCK'):
            return _feature_off()
        path, error = _get_file(
            request, repo_id, request.data.get('path', ''), require_edit=True)
        if error:
            return error
        generation = request.data.get('generation', '')
        if not generation:
            return api_error(status.HTTP_400_BAD_REQUEST, 'generation required.')
        result = service.release_checkout(
            repo_id, path, request.user.username, generation)
        if not result.get('ok'):
            if result.get('reason') == 'not_owner_or_stale':
                return api_error(status.HTTP_409_CONFLICT,
                                 'The file is not locked by the current user.')
            return api_error(status.HTTP_503_SERVICE_UNAVAILABLE,
                             'File-lock service is unavailable.')
        return Response(status=status.HTTP_204_NO_CONTENT)

    def patch(self, request, repo_id):
        """Renew only the caller's current generation of a lease."""
        if not is_enabled('CF_ENABLE_FILE_LOCK'):
            return _feature_off()
        path, error = _get_file(
            request, repo_id, request.data.get('path', ''), require_edit=True)
        if error:
            return error
        generation = request.data.get('generation', '')
        if not generation:
            return api_error(status.HTTP_400_BAD_REQUEST, 'generation required.')
        result = service.refresh_lock(
            repo_id, path, request.user.username, generation)
        if not result.get('ok'):
            if result.get('reason') == 'not_owner_or_stale':
                return api_error(status.HTTP_409_CONFLICT,
                                 'The file lock is no longer active.')
            return api_error(status.HTTP_503_SERVICE_UNAVAILABLE,
                             'File-lock service is unavailable.')
        return Response(result)


class AdminFileLockForceReleaseView(APIView):
    """Let system administrators release a reviewed, fenced lease."""

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser,)
    throttle_classes = (UserRateThrottle,)

    def post(self, request, repo_id):
        if not is_enabled('CF_ENABLE_FILE_LOCK'):
            return _feature_off()
        path, error = _get_file_for_admin(
            repo_id, request.data.get('path', ''))
        if error:
            return error
        generation = request.data.get('generation', '')
        if not generation:
            return api_error(status.HTTP_400_BAD_REQUEST, 'generation required.')
        reason = request.data.get('reason', '')
        if not isinstance(reason, str):
            return api_error(status.HTTP_400_BAD_REQUEST, 'reason invalid.')
        result = service.force_release_lock(
            repo_id, path, request.user.username, generation, reason)
        if not result.get('ok'):
            if result.get('reason') == 'not_found_or_stale':
                return api_error(status.HTTP_409_CONFLICT,
                                 'The file lock is no longer active.')
            return api_error(status.HTTP_503_SERVICE_UNAVAILABLE,
                             'File-lock service is unavailable.')
        return Response(status=status.HTTP_204_NO_CONTENT)


@method_decorator(login_required, name='dispatch')
@method_decorator(never_cache, name='dispatch')
class FileActionsPageView(APIView):
    """Render the dedicated React action surface for one requested file."""

    authentication_classes = ()
    permission_classes = ()

    def get(self, request):
        return render(request, 'cloudfile_ext/file_actions.html')
