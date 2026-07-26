# -*- coding: utf-8 -*-
"""Search: unlock CE's Pro-gated search API, default to SeaSearch, allow
switching to Meilisearch.

Two independent things happen here, and only the first needs a code change at
all:

* The Pro gate. seahub.api2.views.Search and
  seahub.api2.endpoints.public_repos_search.PublishedRepoSearchView are the
  only two search-adjacent endpoints still requiring IsProVersion -- every
  other one already decides for itself via HAS_FILE_SEARCH /
  HAS_FILE_SEASEARCH (docs/search.md section two). CF_ENABLE_SEARCH controls
  whether that gate is shadowed open at all.

* Which backend answers a query. That is CF_PROVIDER_SEARCH
  (cloudfile_ext.providers), and it defaults to empty, which means "native".
  Concretely: seahub.api2.views.Search.get() (and PublishedRepoSearchView) try
  ``if HAS_FILE_SEARCH: ... elif HAS_FILE_SEASEARCH: ai_search_files(...)``.
  SeaSearch answers through that *second* branch, upstream's own, entirely
  without going through search_files()/cloudfile_ext.hooks -- so leaving
  CF_PROVIDER_SEARCH empty needs zero code here, only the Pro-gate unlock
  above plus SeaSearch being configured in seafevents.conf (cloudfile-docker's
  bootstrap does that from CF_ENABLE_SEARCH/CF_SEASEARCH_TOKEN). Setting
  CF_PROVIDER_SEARCH to 'meilisearch' does two things at once: it makes
  _cf_has_search_provider() widen HAS_FILE_SEARCH to True, which routes
  queries into the *first* branch instead (search_files() ->
  cloudfile_ext.hooks.search_files -> this module's registered provider) --
  and it starts the cf-worker indexer below, since Meilisearch's index is
  built by CloudFile, unlike SeaSearch's which seafevents builds itself.

Known gap, upstream's, not introduced here: the elif HAS_FILE_SEASEARCH branch
does not run Search.get()'s is_invisible_path filtering, so a directory ACL's
`invisible` paths (docs/acl-semantics.md) are not excluded from native SeaSearch
results the way they are from the ES/meilisearch branch (which does run that
filtering, being the same branch as ES). Deployments running CF_ENABLE_DIR_ACL
together with search should prefer CF_PROVIDER_SEARCH=meilisearch, or wait for
an upstream fix, until this is resolved -- see docs/search.md.

See docs/search.md for the full design and docs/FEATURES.md item 40.
"""


def register(registry):
    from cloudfile_ext.features import is_enabled

    if not is_enabled('CF_ENABLE_SEARCH'):
        return

    from django.conf import settings
    from django.urls import path

    from cloudfile_ext.search.views import Search, PublishedRepoSearchView

    # Always shadow both Pro-gated endpoints once the capability is on,
    # regardless of which backend answers -- the gate and the backend
    # selection are orthogonal (see module docstring).
    registry.register_urls([
        path('api2/search/', Search.as_view(), name='cloudfile-search'),
        path('api/v2.1/published-repo-search/',
             PublishedRepoSearchView.as_view(),
             name='cloudfile-published-repo-search'),
    ])

    if getattr(settings, 'CF_PROVIDER_SEARCH', '') != 'meilisearch':
        # Empty (or any other value) means native SeaSearch/Elasticsearch --
        # no provider to register, no indexer to run. An unrecognised
        # non-empty value is not caught here; it surfaces as
        # cloudfile_ext.providers.UnknownProvider the first time a query
        # actually needs a provider, per that exception's own docstring.
        return

    from cloudfile_ext.search.backends.meilisearch import MeilisearchProvider
    from cloudfile_ext.search.indexer import TASK_NAME, index_tick

    registry.register_search_provider('meilisearch', MeilisearchProvider())
    registry.register_periodic_task(TASK_NAME, _index_interval(), index_tick)


def _index_interval():
    import logging

    from django.conf import settings

    logger = logging.getLogger(__name__)
    try:
        return max(15, int(getattr(settings, 'CF_SEARCH_INDEX_INTERVAL', 60)))
    except (TypeError, ValueError):
        logger.warning('CF_SEARCH_INDEX_INTERVAL is not a number; using 60s')
        return 60
