# -*- coding: utf-8 -*-
"""Read-only shadows of the native library browser endpoints.

The synthetic repo id lets an external source travel through Seahub's normal
library routes, but it must never reach ``seafile_api``: that API assumes a
commit tree and would turn a harmless browse into a 404/500. These views run
first (rooturl.py's extension ordering), answer only synthetic ids, and defer
unchanged requests to upstream views.

Answering a synthetic id is not enough on its own: the native React library view
consumes these payloads directly, so the fields it reads have to keep the native
shapes -- `parent_dir` with a trailing slash, and `with_parents` expanded to the
ancestor chain. Both are covered by tests/e2e/external_sources_matrix.py.
"""

import os
import posixpath
from urllib.parse import urlencode

from rest_framework import status
from rest_framework.response import Response

from seahub.api2.utils import api_error
from seahub.api2.endpoints.dir import DirView as NativeDirView
from seahub.api2.endpoints.file import FileView as NativeFileView
from seahub.api2.endpoints.repos import (
    RepoView as NativeRepoView, ReposView as NativeReposView,
)
from seahub.api2.endpoints.dir import DirDetailView as NativeDirDetailView
from seahub.api2.endpoints.file_tag import (
    RepoFileTagsView as NativeRepoFileTagsView,
)
from seahub.api2.endpoints.repo_tags import RepoTagsView as NativeRepoTagsView
from seahub.api2.views import (
    FileDetailView as NativeFileDetailView, FileView as NativeApi2FileView,
)
from seahub.utils.timeutils import timestamp_to_isoformat_timestr

from cloudfile_ext.external_sources import paths, service
from cloudfile_ext.external_sources.models import ExternalSource
from cloudfile_ext.external_sources.providers import SourceError, SourceNotFound


def _external_source(request, repo_id, path='/'):
    """Return ``(source, permission, error)``; invisible looks nonexistent."""
    source = ExternalSource.objects.by_repo_id(repo_id)
    if source is None:
        return None, None, None
    if not source.enabled:
        return source, None, api_error(status.HTTP_404_NOT_FOUND, 'Library not found.')
    permission = service.permission_for(
        request.user.username, source, path,
        is_staff=bool(getattr(request.user, 'is_staff', False)))
    if permission is None:
        return source, None, api_error(status.HTTP_404_NOT_FOUND, 'Library not found.')
    return source, permission, None


def _read_only():
    return api_error(status.HTTP_403_FORBIDDEN,
                     'External sources are read-only.')


def _path(request, key='p', required=False):
    try:
        value = paths.normalize_rel_path(request.GET.get(key, ''))
    except paths.UnsafePath as exc:
        return None, api_error(status.HTTP_400_BAD_REQUEST, '%s invalid: %s' % (key, exc))
    if required and value == '/':
        return None, api_error(status.HTTP_400_BAD_REQUEST, '%s is required.' % key)
    return value, None


def _list_with_parents(request, source, path, with_parents):
    """``[(directory, entry), ...]`` for one directory, or for its whole chain.

    Native Seahub answers ``with_parents=1`` with the dirents of ``/``, ``/a``
    and ``/a/b`` as one flat list, each entry carrying its own ``parent_dir``.
    The React folder tree groups that list by ``parent_dir`` and fills one node
    per directory, so the entries must arrive ancestor-first for every node to
    exist by the time it is looked up. Answering with the requested directory
    alone left every ancestor node permanently unloaded.

    An ancestor is expanded only when the caller may read it: letting the flag
    enumerate a parent that a directory ACL hides would undo that rule by
    naming a path below it. When any ancestor is unreadable the whole expansion
    is dropped, which is the previous behaviour and therefore leaks nothing.
    """
    listing = service.list_dir(source, path)
    if not with_parents or path == '/':
        return [(path, entry) for entry in listing]

    is_staff = bool(getattr(request.user, 'is_staff', False))
    dirs = service.ancestor_dirs(path)
    for directory in dirs:
        if service.permission_for(request.user.username, source, directory,
                                  is_staff=is_staff) is None:
            return [(path, entry) for entry in listing]

    expanded = []
    for directory in dirs:
        # The requested directory was already read above; only the ancestors
        # cost an extra listing.
        entries = listing if directory == path else service.list_dir(source, directory)
        for entry in entries:
            expanded.append((directory, entry))
    return expanded


def _entry(source, entry, parent, permission):
    path = '/' + entry.name if parent == '/' else posixpath.join(parent, entry.name)
    result = {
        'type': 'dir' if entry.is_dir else 'file',
        # There is no content-addressed object id. Empty is deliberate: it
        # prevents a caller from treating an arbitrary NAS file as a block.
        'id': '',
        'name': entry.name,
        'mtime': entry.mtime,
        'permission': permission,
        'parent_dir': service.native_parent_dir(parent),
        'path': path,
        'starred': False,
    }
    if not entry.is_dir:
        # `can_edit: False` is a true statement about a read-only source.
        # There is deliberately no `can_preview`: preview does work
        # (the download URL below serves the bytes), and nothing in the
        # frontend reads either flag, so a `False` here would only be a
        # lie waiting for the first caller that trusts it.
        result.update({'size': entry.size, 'is_locked': False,
                       'can_edit': False})
    return result


def _source_repo(source, permission):
    return {
        'repo_id': source.repo_id,
        'repo_name': source.name,
        'repo_type': 'external',
        'owner_email': '',
        'owner_name': 'External source',
        'owner_contact_email': '',
        'owner_avatar': '',
        'size': 0,
        'encrypted': False,
        'file_count': -1,
        'permission': permission,
        'no_quota': True,
        'is_admin': False,
        'is_virtual': False,
        'has_been_shared_out': False,
        'lib_need_decrypt': False,
        'last_modified': timestamp_to_isoformat_timestr(source.mtime),
        'status': 0,
        'enable_onlyoffice': False,
        'monitored': False,
        'is_external_source': True,
        'external_source_id': source.id,
    }


class ExternalReposView(NativeReposView):
    """Append sources the current user can read to native `/api/v2.1/repos/`."""

    def get(self, request):
        response = super().get(request)
        if response.status_code != status.HTTP_200_OK:
            return response
        requested = request.GET.getlist('type', '')
        # An external source has no owner/group/public classification. Treat
        # it as a read-only shared library and do not inject it into `mine`.
        if requested and 'shared' not in requested:
            return response
        name_contains = request.GET.get('nameContains', '').lower()
        extra = []
        is_staff = bool(getattr(request.user, 'is_staff', False))
        for source in ExternalSource.objects.enabled_sources():
            permission = service.permission_for(request.user.username, source,
                                                is_staff=is_staff)
            if permission is None:
                continue
            if name_contains and name_contains not in source.name.lower():
                continue
            extra.append(_source_repo(source, permission))
        response.data['repos'].extend(extra)
        return response


class ExternalRepoView(NativeRepoView):

    def get(self, request, repo_id):
        source, permission, error = _external_source(request, repo_id)
        if source is None:
            return super().get(request, repo_id)
        if error:
            return error
        return Response(_source_repo(source, permission))

    def post(self, request, repo_id):
        source, _permission, _error = _external_source(request, repo_id)
        return _read_only() if source is not None else super().post(request, repo_id)

    def delete(self, request, repo_id):
        source, _permission, _error = _external_source(request, repo_id)
        return _read_only() if source is not None else super().delete(request, repo_id)


class ExternalDirView(NativeDirView):

    def get(self, request, repo_id):
        path, path_error = _path(request)
        if path_error:
            return path_error
        source, permission, error = _external_source(request, repo_id, path)
        if source is None:
            return super().get(request, repo_id)
        if error:
            return error
        if request.GET.get('recursive', '0') == '1':
            return api_error(status.HTTP_400_BAD_REQUEST,
                             'Recursive listing is not available for external sources.')
        # `with_parents` is answered rather than ignored: the native side tree
        # sends it on every navigation into a subdirectory, and without the
        # ancestor entries its nodes can never be filled.
        with_parents = request.GET.get('with_parents', '0') == '1'
        try:
            listing = _list_with_parents(request, source, path, with_parents)
        except SourceNotFound:
            return api_error(status.HTTP_404_NOT_FOUND, 'Folder not found.')
        except (SourceError, paths.UnsafePath):
            return api_error(status.HTTP_503_SERVICE_UNAVAILABLE,
                             'Source is currently unreachable.')
        request_type = request.GET.get('t', '')
        values = [_entry(source, entry, directory, permission)
                  for directory, entry in listing
                  if not request_type or
                  (request_type == 'd' and entry.is_dir) or
                  (request_type == 'f' and not entry.is_dir)]
        return Response({'user_perm': permission, 'dir_id': '',
                         'dirent_list': values, 'external_source': True})

    def post(self, request, repo_id):
        source, _permission, _error = _external_source(request, repo_id)
        return _read_only() if source is not None else super().post(request, repo_id)


class ExternalFileView(NativeFileView):

    def get(self, request, repo_id):
        path, path_error = _path(request, required=True)
        if path_error:
            return path_error
        source, permission, error = _external_source(request, repo_id, path)
        if source is None:
            return super().get(request, repo_id)
        if error:
            return error
        try:
            item = service.backend_for(source).stat(source.root_path, path)
        except SourceNotFound:
            return api_error(status.HTTP_404_NOT_FOUND, 'File not found.')
        except (SourceError, paths.UnsafePath):
            return api_error(status.HTTP_503_SERVICE_UNAVAILABLE,
                             'Source is currently unreachable.')
        if item.is_dir:
            return api_error(status.HTTP_400_BAD_REQUEST, 'p is a directory.')
        return Response(_entry(source, item, posixpath.dirname(path) or '/', permission))

    def post(self, request, repo_id):
        source, _permission, _error = _external_source(request, repo_id)
        return _read_only() if source is not None else super().post(request, repo_id)


class ExternalApi2FileView(NativeApi2FileView):
    """Return the authenticated Hub stream URL, never a Go fileserver token."""

    def get(self, request, repo_id, format=None):
        path, path_error = _path(request, required=True)
        if path_error:
            return path_error
        source, _permission, error = _external_source(request, repo_id, path)
        if source is None:
            return super().get(request, repo_id, format=format)
        if error:
            return error
        try:
            item = service.backend_for(source).stat(source.root_path, path)
        except SourceNotFound:
            return api_error(status.HTTP_404_NOT_FOUND, 'File not found.')
        except (SourceError, paths.UnsafePath):
            return api_error(status.HTTP_503_SERVICE_UNAVAILABLE,
                             'Source is currently unreachable.')
        if item.is_dir:
            return api_error(status.HTTP_400_BAD_REQUEST, 'p is a directory.')
        target = '/api/v2.1/cloudfile/external-sources/%s/file/?%s' % (
            source.id, urlencode({'p': path, 'op': 'download'}))
        return Response(request.build_absolute_uri(target))

    def post(self, request, repo_id, format=None):
        source, _permission, _error = _external_source(request, repo_id)
        return _read_only() if source is not None else super().post(request, repo_id, format=format)


class ExternalFileDetailView(NativeFileDetailView):

    def get(self, request, repo_id, format=None):
        path, path_error = _path(request, required=True)
        if path_error:
            return path_error
        source, permission, error = _external_source(request, repo_id, path)
        if source is None:
            return super().get(request, repo_id, format=format)
        if error:
            return error
        try:
            item = service.backend_for(source).stat(source.root_path, path)
        except SourceNotFound:
            return api_error(status.HTTP_404_NOT_FOUND, 'File not found.')
        except (SourceError, paths.UnsafePath):
            return api_error(status.HTTP_503_SERVICE_UNAVAILABLE,
                             'Source is currently unreachable.')
        if item.is_dir:
            return api_error(status.HTTP_400_BAD_REQUEST, 'p is a directory.')
        return Response({
            'type': 'file', 'id': '', 'name': os.path.basename(path),
            'permission': permission, 'mtime': item.mtime,
            'last_modified': timestamp_to_isoformat_timestr(item.mtime),
            'last_modifier_email': '', 'last_modifier_name': '',
            'last_modifier_contact_email': '', 'size': item.size,
            'is_external_source': True,
        })


def _null_payload_for(request, repo_id, native_get, payload):
    """Answer a synthetic repo with `payload`, or delegate a real one.

    Three native endpoints the library view calls on paths an external source
    cannot serve are handled by a near-identical body, so the shared shape is
    written once. Each caller still declares its own payload: a wildcard
    "return empty for anything unshadowed" would turn a real fault -- a dropped
    mount, a broken index -- into what looks like an empty result, which is the
    one reading this module must never produce.
    """
    source, _permission, error = _external_source(request, repo_id)
    if source is None:
        return native_get(request, repo_id)
    if error:
        return error
    return Response(payload)


class ExternalRepoTagsView(NativeRepoTagsView):
    """`GET /repo-tags/` for an external source: an empty tag set.

    The library view calls this on every directory load (`loadDirData`), and
    the upstream view answers 404 for a repo id that names no row in seafile-db.
    The frontend's handler is a `.catch(... toaster.danger)`, so before this
    shadow every visit to an external source opened with a red error toast.
    Returning the native shape with no tags is also the truthful answer: an
    external source does not enter the tag model at all.
    """

    def get(self, request, repo_id):
        return _null_payload_for(request, repo_id, super().get, {'repo_tags': []})

    def post(self, request, repo_id):
        source, _permission, _error = _external_source(request, repo_id)
        return _read_only() if source is not None else super().post(request, repo_id)

    def put(self, request, repo_id):
        source, _permission, _error = _external_source(request, repo_id)
        return _read_only() if source is not None else super().put(request, repo_id)


class ExternalFileTagsView(NativeRepoFileTagsView):
    """`GET /file-tags/` for an external source: an empty tag set.

    Reached from the preview path (`showFile`), which also reported the 404 as
    an error toast while the preview itself worked.
    """

    def get(self, request, repo_id):
        return _null_payload_for(request, repo_id, super().get, {'file_tags': []})

    def post(self, request, repo_id):
        source, _permission, _error = _external_source(request, repo_id)
        return _read_only() if source is not None else super().post(request, repo_id)


class ExternalDirDetailView(NativeDirDetailView):
    """`GET /dir/detail/` for an external source.

    The dirent detail panel asks this for a selected folder. The native view
    returns exactly these three fields, so the shadow returns the same three
    from the provider's `stat` rather than a 404.
    """

    def get(self, request, repo_id):
        path, path_error = _path(request, key='path', required=True)
        if path_error:
            return path_error
        source, permission, error = _external_source(request, repo_id, path)
        if source is None:
            return super().get(request, repo_id)
        if error:
            return error
        try:
            item = service.backend_for(source).stat(source.root_path, path)
        except SourceNotFound:
            return api_error(status.HTTP_404_NOT_FOUND, 'Folder not found.')
        except (SourceError, paths.UnsafePath):
            return api_error(status.HTTP_503_SERVICE_UNAVAILABLE,
                             'Source is currently unreachable.')
        if not item.is_dir:
            return api_error(status.HTTP_400_BAD_REQUEST, 'path is not a directory.')
        # 修改逻辑/原因（2026-09-23 review）：原生 DirDetailView 返回 5 个字段
        # （repo_id/path/name/mtime/permission），详情面板把响应整体存进 state，
        # 少了 repo_id/path 会渲染出 undefined。path 用原生格式（带尾斜杠）。
        return Response({
            'repo_id': repo_id,
            'path': service.native_parent_dir(path),
            'name': item.name,
            'mtime': timestamp_to_isoformat_timestr(item.mtime),
            'permission': permission,
        })
