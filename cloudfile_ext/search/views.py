# -*- coding: utf-8 -*-
"""URL-shadow views that swap IsProVersion for IsSearchAvailable.

Both classes are pure permission overrides -- everything else (query parsing,
Seahub's own permission-aware repo scoping, response shape) is inherited
unchanged from upstream. That is deliberate: rewriting either view risks
diverging from the repo-scoping logic that keeps a search from leaking files
across libraries, and there is nothing about search *becoming available* on
CE that should change how a request is handled once it is let through.

Registered under the same URL as the upstream view (cloudfile_ext.urls is
prepended to Seahub's own patterns -- see seahub/utils/rooturl.py), so no
upstream file is edited: search.md section 3 has the full reasoning.
"""

from rest_framework import status
from rest_framework.permissions import IsAuthenticated, IsAuthenticatedOrReadOnly

from seahub.api2.utils import api_error

from seahub.api2.views import Search as _UpstreamSearch
from seahub.api2.endpoints.public_repos_search import (
    PublishedRepoSearchView as _UpstreamPublishedRepoSearchView,
)

from cloudfile_ext.search.permissions import IsSearchAvailable


class Search(_UpstreamSearch):
    permission_classes = (IsAuthenticated, IsSearchAvailable)

    def get(self, request, *args, **kwargs):
        """Fail loudly when this deployment cannot answer the question.

        修改逻辑/原因（2026-09-12 降级修复）：上游 Search.get() 把 search_files()
        整段包在 `except Exception: results, total = [], 0` 里，因此"没有 provider /
        没有索引"与"确实没有匹配"对用户完全一样（都是 0 条）。这里在进入上游之前先判定
        后端状态：
          * none     -> 501，明确"搜索未启用"；
          * db-tags  -> 只支持标签/创建者过滤，纯全文请求返回 501 并提示如何启用索引；
                       带 tags/creator 的请求继续交给上游（由内置后端作答）。
        """
        from cloudfile_ext.hooks import search_backend_state
        state = search_backend_state()
        if state == 'none':
            return api_error(
                status.HTTP_501_NOT_IMPLEMENTED,
                'file search is not enabled on this deployment '
                '(no search provider selected; set CF_PROVIDER_SEARCH or turn on '
                'CF_SEARCH_DB_FALLBACK)')
        if state == 'db-tags':
            has_filter = bool(request.GET.get('tags', '').strip()
                              or request.GET.get('creator_emails', '').strip())
            if not has_filter:
                return api_error(
                    status.HTTP_501_NOT_IMPLEMENTED,
                    'full-text search requires an index provider '
                    '(CF_PROVIDER_SEARCH=meilisearch); tag search is available '
                    'via the tags= parameter')
        return super(Search, self).get(request, *args, **kwargs)


class PublishedRepoSearchView(_UpstreamPublishedRepoSearchView):
    permission_classes = (IsAuthenticatedOrReadOnly, IsSearchAvailable)
