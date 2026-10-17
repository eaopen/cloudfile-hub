"""Authenticated bounded search used by the existing Etech file browser."""
import logging
from uuid import UUID

from django.conf import settings
from django.core import signing
from rest_framework.permissions import IsAuthenticated
from cloudfile_ext.v2.permissions import SubjectReady
from rest_framework.response import Response
from rest_framework.views import APIView
from seahub.api2.authentication import TokenAuthentication, SessionAuthentication
from seahub.api2.throttling import UserRateThrottle
from seahub.utils.timeutils import timestamp_to_isoformat_timestr

from .client import ExistingMeiliIndex, SearchUnavailable, SearchWindowExceeded, normalize_path
from .paging import page
from .runtime import AccessDenied, NativeAuthority

logger = logging.getLogger(__name__)


def configured_client():
    # Search is an external capability, not a second ENABLE/PROVIDER toggle.
    # Missing endpoint or failed Meilisearch requests affect Search only.
    if not getattr(settings, 'CF_MEILISEARCH_URL', ''):
        raise SearchUnavailable('Meilisearch not configured')
    return ExistingMeiliIndex(getattr(settings, 'CF_MEILISEARCH_URL', ''),
                              getattr(settings, 'CF_MEILISEARCH_API_KEY', ''),
                              getattr(settings, 'CF_MEILISEARCH_INDEX', 'cloudfile_files'))


class SearchQuery(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, SubjectReady)
    throttle_classes = (UserRateThrottle,)

    def get(self, request):
        try:
            args = request.query_params
            if set(args) - {'repo_id', 'q', 'path', 'limit', 'cursor'} or any(len(args.getlist(k)) != 1 for k in args):
                raise ValueError()
            rid, query = args.get('repo_id'), args.get('q')
            if str(UUID(rid)) != rid or not isinstance(query, str) or not query.strip() or len(query) > 512:
                raise ValueError()
            query.encode('utf-8')
            root, limit = normalize_path(args.get('path', '/')), int(args.get('limit', '50'))
            if not 1 <= limit <= 100:
                raise ValueError()
            authority = NativeAuthority(request.user.username, rid, root)
            binding = dict(user=request.user.username, repo=rid, q=query, root=root,
                           limit=limit, version=authority.version)
            offset = 0
            cursor = args.get('cursor')
            if cursor:
                if len(cursor) > 4096:
                    raise ValueError()
                saved = signing.loads(cursor, salt='cloudfile-v2-search', max_age=300)
                if saved['scope'] != binding or type(saved['offset']) is not int or saved['offset'] < 0:
                    raise ValueError()
                offset = saved['offset']
            client = configured_client()
            result = page(limit=limit, offset=offset,
                          fetch_candidates=lambda start, count: client.page(rid, root, query, start, count),
                          resolve_authorized=authority.resolve)
            data = []
            for item in result['items']:
                ref = {k: item[k] for k in ('repo_id', 'path', 'kind')}
                data.append(dict(path=item['path'], type='folder' if item['kind'] == 'dir' else 'file',
                                 size=item['size'], mtime=timestamp_to_isoformat_timestr(item['mtime']),
                                 tags=item['tags'], matched_tags=item['matched_tags'],
                                 authorization=dict(**ref, visible=True, read=True)))
            next_offset = result['next_offset']
            payload = dict(data=data, provider='meilisearch', fallback=False, scope='subtree', path=root,
                           authorization=dict(version=1, repo_id=rid, policy_revision=authority.version,
                                              head=authority.snapshot['head']),
                           next_cursor=signing.dumps(dict(scope=binding, offset=next_offset),
                                                    salt='cloudfile-v2-search', compress=True) if next_offset is not None else None)
            response = Response(payload)
            response.accepted_renderer = request.accepted_renderer
            response.accepted_media_type = request.accepted_media_type
            response.renderer_context = self.get_renderer_context()
            response.render()
            authority.assert_current(result['items'])
        except (ValueError, TypeError, KeyError, UnicodeError, signing.BadSignature):
            response = Response(dict(error_code='INVALID_SEARCH', error_msg='Invalid search parameters or expired cursor'), status=400)
        except AccessDenied:
            response = Response(dict(error_code='ACCESS_DENIED', error_msg='Search access denied'), status=403)
        except SearchWindowExceeded:
            response = Response(dict(error_code='SEARCH_WINDOW_LIMIT', error_msg='Narrow the search scope or query'), status=409)
        except Exception:
            logger.exception('V2 search unavailable')
            response = Response(dict(error_code='SEARCH_UNAVAILABLE', error_msg='Search unavailable'), status=503)
        response['Cache-Control'] = 'no-store'
        return response
