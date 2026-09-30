"""Authenticated compatibility search for current CE installations.

This keeps the native identity/ACL contract separate from OIDC resource search.
Its result proof lets EAP consume exact object decisions without parent grants.
"""
from django.conf import settings
from django.core import signing
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from seahub.api2.authentication import TokenAuthentication
from seahub.api2.throttling import UserRateThrottle
from cloudfile_ext.hooks import check_permission
from seahub.utils.timeutils import timestamp_to_isoformat_timestr
from seaserv import seafile_api
from .backends.meilisearch import client_from_settings
from .bounded import SearchFailure, query_page, validate
from .access import SearchAccess
from .native_many import NativePermissionMany
from .access_runtime import read_snapshot


class BoundedSearch(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    def get(self, request):
        try:
            repo_id, q, path, limit = validate(request.GET.get('repo_id'), request.GET.get('q'),
                request.GET.get('path', '/'), int(request.GET.get('limit', '50')))
            repo = seafile_api.get_repo(repo_id)
            if repo is None:
                raise SearchFailure('NOT_FOUND', 'Library not found', 404)
            username = request.user.username
            # The native transport retains every C provider; Hub hooks remain
            # per-path narrowing checks here, in both independent passes.
            native_many = NativePermissionMany(repo_id, username,
                seafile_api.cf_check_permissions_many, check_permission)
            access = SearchAccess(lambda: read_snapshot(username, repo_id), None,
                native_many=native_many)
            scope = dict(user=username, repo=repo_id, q=q, path=path, limit=limit,
                head=repo.head_cmmt_id, policy=access.version)
            offset, provider = 0, None
            cursor = request.GET.get('cursor')
            if cursor:
                if len(cursor) > 4096:
                    raise signing.BadSignature()
                saved = signing.loads(cursor, salt='cloudfile-bounded-search', max_age=300)
                if saved.get('scope') != scope:
                    raise signing.BadSignature()
                offset, provider = saved['offset'], saved['provider']
            client = client_from_settings() if getattr(settings, 'CF_PROVIDER_SEARCH', '') == 'meilisearch' else None
            result = query_page(repo_id=repo_id, q=q, path=path, limit=limit, offset=offset,
                provider=provider, client=client, can_read=access, prepare_paths=access.prepare_many,
                list_directory=lambda p, start, size: seafile_api.list_dir_by_path(repo_id, p, start, size),
                resolve_item=lambda p: seafile_api.get_dirent_by_path(repo_id, p))
            for item in result['data']:
                item['mtime'] = timestamp_to_isoformat_timestr(item['mtime'])
                # This proof is private until serialization and both final
                # checks succeed. Failure discards the entire prepared response;
                # a parent grant never stands in for an exact object decision.
                item['authorization'] = dict(repo_id=repo_id, path=item['path'],
                    kind='dir' if item['type'] == 'folder' else 'file', visible=True, read=True)
            result['authorization'] = dict(version=1, repo_id=repo_id,
                policy_revision=access.version, head=scope['head'])
            next_offset = result.pop('next_offset')
            result['next_cursor'] = signing.dumps(dict(scope=scope, offset=next_offset, provider=result['provider']),
                salt='cloudfile-bounded-search', compress=True) if next_offset is not None else None
            response = Response(result)
            # DRF normally renders after get() returns. Eagerly render with the
            # already negotiated renderer so metadata/serialization mutations
            # precede the second real native pass. No bytes are published yet.
            response.accepted_renderer = request.accepted_renderer
            response.accepted_media_type = request.accepted_media_type
            response.renderer_context = self.get_renderer_context()
            response.render()
            access.assert_current()
            current = seafile_api.get_repo(repo_id)
            if current is None or current.head_cmmt_id != scope['head']:
                raise SearchFailure('SEARCH_CHANGED', 'Library or permissions changed; search again')
            # This bounds preparation, not writers: changes after the final
            # snapshot/head reads remain outside any legacy consistency lease.
        except (signing.BadSignature, KeyError, TypeError, ValueError):
            response = Response(dict(error_code='INVALID_CURSOR', error_msg='Invalid search parameters or expired cursor'), status=400)
        except SearchFailure as exc:
            response = Response(dict(error_code=exc.code, error_msg=exc.message), status=exc.status)
        except Exception:
            response = Response(dict(error_code='SEARCH_UNAVAILABLE', error_msg='Search unavailable'), status=503)
        response['Cache-Control'] = 'no-store'
        return response
