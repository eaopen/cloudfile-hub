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

from rest_framework.permissions import IsAuthenticated, IsAuthenticatedOrReadOnly

from seahub.api2.views import Search as _UpstreamSearch
from seahub.api2.endpoints.public_repos_search import (
    PublishedRepoSearchView as _UpstreamPublishedRepoSearchView,
)

from cloudfile_ext.search.permissions import IsSearchAvailable


class Search(_UpstreamSearch):
    permission_classes = (IsAuthenticated, IsSearchAvailable)


class PublishedRepoSearchView(_UpstreamPublishedRepoSearchView):
    permission_classes = (IsAuthenticatedOrReadOnly, IsSearchAvailable)
