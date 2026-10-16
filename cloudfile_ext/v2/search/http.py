"""Authenticated bounded search used by the existing Etech file browser."""
import logging
from uuid import UUID

from django.conf import settings
from django.core import signing
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from seahub.api2.authentication import TokenAuthentication, SessionAuthentication
from seahub.api2.throttling import UserRateThrottle
from seahub.utils.timeutils import timestamp_to_isoformat_timestr

from .client import ExistingMeiliIndex, SearchUnavailable, SearchWindowExceeded, normalize_path, search_filters
from .paging import page
from .runtime import AccessDenied, NativeAuthority

logger = logging.getLogger(__name__)


def configured_client():
    if not getattr(settings, 'CF_ENABLE_SEARCH', False) or getattr(settings, 'CF_PROVIDER_SEARCH', '') != 'meilisearch':
        raise SearchUnavailable('search is disabled')
    return ExistingMeiliIndex(getattr(settings, 'CF_MEILISEARCH_URL', ''),
                              getattr(settings, 'CF_MEILISEARCH_API_KEY', ''),
                              getattr(settings, 'CF_MEILISEARCH_INDEX', 'cloudfile_files'))


class SearchQuery(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    def get(self, request):
        try:
            args = request.query_params
            if set(args) - {'repo_id', 'q', 'path', 'limit', 'cursor', 'kind', 'extension', 'tag'} or any(len(args.getlist(k)) != 1 for k in args):
                raise ValueError()
            rid, query = args.get('repo_id'), args.get('q')
            if str(UUID(rid)) != rid or not isinstance(query, str) or not query.strip() or len(query) > 512:
                raise ValueError()
            query.encode('utf-8')
            root, limit = normalize_path(args.get('path', '/')), int(args.get('limit', '50'))
            if not 1 <= limit <= 100:
                raise ValueError()
            kind, extension, tag = search_filters(kind=args.get('kind'),
                                                  extension=args.get('extension'),
                                                  tag=args.get('tag'))
            authority = NativeAuthority(request.user.username, rid, root)
            binding = dict(user=request.user.username, repo=rid, q=query, root=root,
                           limit=limit, version=authority.version)
            filters = dict(kind=kind, extension=extension, tag=tag)
            if any(value is not None for value in filters.values()):
                binding['filters'] = filters
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
            def fetch_candidates(start, count):
                if 'filters' not in binding:
                    return client.page(rid, root, query, start, count)
                return client.page(rid, root, query, start, count, **filters)

            def resolve_authorized(references):
                # Keep the existing fail-closed cf_dir_acl subtree policy in
                # NativeAuthority. These filters only NARROW its results.
                current = authority.resolve(references)
                if 'filters' not in binding:
                    return current
                filtered = []
                for item in current:
                    if item is None:
                        filtered.append(None)
                    elif (kind is not None and item['kind'] != kind) or (
                            extension is not None and
                            (item['kind'] != 'file' or
                             item['path'].rsplit('/', 1)[-1].rsplit('.', 1)[-1].lower() != extension)
                    ) or (tag is not None and tag not in item['tags']):
                        filtered.append(None)
                    else:
                        filtered.append(item)
                return filtered

            result = page(limit=limit, offset=offset,
                          fetch_candidates=fetch_candidates,
                          resolve_authorized=resolve_authorized)
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
