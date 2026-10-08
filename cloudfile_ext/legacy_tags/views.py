"""Authenticated legacy FileTag batch adapter; old single-item URLs are intact."""
import stat
from types import SimpleNamespace

from rest_framework.authentication import SessionAuthentication
from rest_framework.parsers import BaseParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from seahub.api2.authentication import TokenAuthentication
from seahub.api2.throttling import UserRateThrottle
from seaserv import seafile_api

from cloudfile_ext.features import is_enabled
from cloudfile_ext.hooks import check_permission
# These existing 4B components are intentionally reused unchanged: native
# identities/writers cannot safely be moved into 4A's OIDC consistency scope.
from cloudfile_ext.search.access import SearchAccess
from cloudfile_ext.search.access_runtime import read_snapshot
from cloudfile_ext.search.native_many import NativePermissionMany
from .contract import capability, request_body, MAX_BYTES, MAX_RESPONSE_BYTES
from .service import resolve
from .store import tags_many


def _stamp(repo):
    return (repo.head_cmmt_id, repo.is_virtual,
            repo.origin_repo_id if repo.is_virtual else None,
            repo.origin_path if repo.is_virtual else None)


class LegacyTagBatchJSONParser(BaseParser):
    media_type = 'application/json'

    def parse(self, stream, media_type=None, parser_context=None):
        # SessionAuthentication's CSRF check can parse request.POST before the
        # view runs. Cache bounded raw bytes as request.data so that validation
        # still sees duplicate JSON keys, instead of rereading a consumed body.
        return stream.read(MAX_BYTES + 1)


class LegacyFileTagsBatch(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    parser_classes = (LegacyTagBatchJSONParser,)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    def get(self, request):
        # A versioned, per-request capability probe avoids guessing from a
        # general TAGS flag (which can describe another tag model entirely).
        response = Response(capability() if is_enabled('CF_ENABLE_TAGS') else
                            dict(error='LEGACY_TAG_BATCH_UNAVAILABLE'),
                            status=200 if is_enabled('CF_ENABLE_TAGS') else 503)
        response['Cache-Control'] = 'no-store'
        return response

    def post(self, request):
        if not is_enabled('CF_ENABLE_TAGS'):
            return Response(dict(error='LEGACY_TAG_BATCH_UNAVAILABLE'), status=503,
                            headers={'Cache-Control': 'no-store'})
        try:
            repo_id, items = request_body(request.data)
        except Exception:
            return Response(dict(error='INVALID_LEGACY_TAG_BATCH'), status=400,
                            headers={'Cache-Control': 'no-store'})
        try:
            repo = seafile_api.get_repo(repo_id)
            if repo is None:
                return Response(dict(error='LIBRARY_NOT_FOUND'), status=404,
                                headers={'Cache-Control': 'no-store'})
            stamp = _stamp(repo)
            username = request.user.username
            access = SearchAccess(lambda: read_snapshot(username, repo_id), None,
                native_many=NativePermissionMany(repo_id, username,
                    seafile_api.cf_check_permissions_many, check_permission))
            def lookup(path, is_dir):
                if path == '/' and is_dir:
                    return SimpleNamespace(mode=stat.S_IFDIR) if seafile_api.get_dir_id_by_path(repo_id, '/') else None
                return seafile_api.get_dirent_by_path(repo_id, path)
            result = resolve(repo_id, items, access, lookup,
                             lambda allowed: tags_many(repo_id, repo, allowed))
            response = Response(result)
            response.accepted_renderer = request.accepted_renderer
            response.accepted_media_type = request.accepted_media_type
            response.renderer_context = self.get_renderer_context()
            response.render()
            if len(response.content) > MAX_RESPONSE_BYTES:
                raise ValueError('Legacy tag response too large')
            # Both real native passes remain necessary. Render first, then
            # snapshot/native/snapshot/head checks; this is not a writer lease.
            access.assert_current()
            current = seafile_api.get_repo(repo_id)
            if current is None or _stamp(current) != stamp:
                raise ValueError('Library changed')
        except Exception:
            # Shared SQL/authorization failures discard this HTTP group, never
            # leak partially authorized tags; EAP marks its items unavailable.
            response = Response(dict(error='LEGACY_TAG_BATCH_UNAVAILABLE'), status=503)
        response['Cache-Control'] = 'no-store'
        return response
