# -*- coding: utf-8 -*-
"""Entry points that patched Seahub code calls into.

Keeping these in one module means the patches in seahub/ stay one-liners that
never need to know which capabilities exist -- adding a capability is a
registration, not another edit to upstream code.

Every function here must behave as a no-op when nothing is registered, since
that is the state of a baseline build with every CF_ENABLE_* switch off.
"""

import logging

from cloudfile_ext import search_query
from cloudfile_ext.registry import SEARCH, registry

logger = logging.getLogger(__name__)


def check_permission(username, repo_id, path, permission):
    """Narrow `permission` through every registered permission hook.

    Called from seahub.views.check_folder_permission. Returns the permission
    unchanged when no capability has registered a hook, which is the case with
    every CF_ENABLE_* switch off.
    """
    if not registry.permission_checks:
        return permission
    return registry.apply_permission_checks(username, repo_id, path, permission)


def has_search_provider():
    """Whether a CloudFile search backend is *configured*.

    Called from seahub.utils to widen HAS_FILE_SEARCH. That flag gates the
    search entry points themselves -- six call sites decide whether to offer
    search at all -- so without this the query hook below would never be
    reached on a CE deployment, which has no Elasticsearch to enable it.

    This deliberately asks configuration, not the registry. seahub.utils is
    imported by whichever module happens to need it first, which can be during
    app population, before CloudFileConfig.ready() has registered anything;
    consulting the registry here would make search silently depend on import
    order. A setting is readable the moment settings are.

    The consequence is that a configured-but-unregistered provider turns the
    entry points on and then fails at query time with UnknownProvider. That is
    the intended trade: loud and attributable beats a search box that quietly
    is not there.
    """
    from cloudfile_ext import providers
    if providers.selected(SEARCH):
        return True
    # 修改逻辑/原因（2026-09-12 降级修复）：内置标签后端不需要任何外部组件，
    # 因此默认开启 fallback 时，只要 CF_ENABLE_SEARCH 打开就能解锁搜索入口——
    # 部署既没有 Elasticsearch 也没有 Meilisearch 时，按标签/创建者查询依然可用，
    # 而不是让用户看到"0 条结果"。
    return _db_fallback_enabled()


def search_files(repos_map, search_path, keyword, obj_desc, start, size,
                 org_id=None, search_filename_only=False, filters=None):
    """Answer a file search, or return None to let Seahub answer it.

    Called from seahub.search.utils.search_files in place of es_search, and
    directly by capabilities that need structured filters. The provider
    returns raw hits; all of Seahub's post-processing (repo resolution,
    virtual-root rewriting, dirent lookup, permission-aware repo scoping)
    still runs on top, so a backend only has to know how to match documents --
    and cannot accidentally bypass the scoping by not reimplementing it.

    `filters` carries user-defined attribute and tag predicates
    (cloudfile_ext.search_query). They are validated against what the provider
    declares it supports *before* the call, so an unsupported predicate fails
    instead of being quietly dropped.

    Returning None -- no provider selected -- leaves native behaviour intact.
    """
    try:
        provider = registry.active_search_provider()
    except Exception:
        # seahub.api2.views wraps its search_files() call in a bare
        # `except Exception: results, total = [], 0`, so an exception raised
        # here reaches the user as an empty result page, not as an error.
        # Logging explicitly is the only channel left that names the cause;
        # without it a mistyped CF_PROVIDER_SEARCH looks exactly like "nothing
        # matched".
        logger.exception(
            'cloudfile search provider unavailable; the native search entry '
            'point will show an empty result set. Check CF_PROVIDER_SEARCH '
            'against the providers listed by /api/v2.1/cloudfile/features/.')
        raise

    if provider is None:
        if filters:
            # 修改逻辑/原因（2026-09-12 降级修复）：原生 ES/SeaSearch 无法表达结构化
            # 过滤（tags/creator），此前直接抛 UnsupportedFilter，被上游 Search 视图的
            # `except Exception` 吞成 total:0，用户看到"没有匹配文件"——而标签确实存在。
            # 现在默认路由到内置 DB 标签后端（seahub 自身标签表即可回答），
            # 只有在 fallback 被显式关闭时才拒绝（拒绝仍然优于静默丢条件）。
            if _db_fallback_enabled():
                db_provider = _db_provider()
                parsed = search_query.parse(filters)
                # 让声明的算子集合决定是否可答：不支持的谓词显式失败，绝不静默丢弃。
                search_query.check_supported(db_provider, parsed)
                return db_provider.search_files(
                    repos_map, search_path, keyword, obj_desc, start, size,
                    org_id, search_filename_only, parsed)
            raise search_query.UnsupportedFilter(
                'structured filters require a CloudFile search provider; '
                'none is selected (CF_PROVIDER_SEARCH) and '
                'CF_SEARCH_DB_FALLBACK is off')
        return None

    filters = search_query.parse(filters)
    search_query.check_supported(provider, filters)

    if not filters:
        # Keep the historical call shape for providers written against it.
        return provider.search_files(repos_map, search_path, keyword, obj_desc,
                                     start, size, org_id, search_filename_only)
    return provider.search_files(repos_map, search_path, keyword, obj_desc,
                                 start, size, org_id, search_filename_only,
                                 filters)


#: Built-in backend that answers tag/creator predicates from Seahub's own tag
#: tables (no external index). Registered by cloudfile_ext.search.
DB_TAGS_PROVIDER = 'db-tags'


def _db_fallback_enabled():
    """Whether the built-in tag backend may answer when no provider is selected."""
    from django.conf import settings
    return getattr(settings, 'CF_SEARCH_DB_FALLBACK', True) is True


def _db_provider():
    """The built-in tag backend, or None when it was never registered."""
    return registry.providers.get(SEARCH, DB_TAGS_PROVIDER)


def _native_search_available():
    """Whether upstream's own Elasticsearch/SeaSearch backend is configured.

    Read lazily: seahub.search.utils imports this module, so importing it at
    module level would be circular.
    """
    try:
        from seahub.search.utils import es_search
        return es_search is not None
    except Exception:
        return False


def search_backend_state():
    """Which backend answers a search request right now.

    Used by the shadowed search views to fail loudly (501) instead of letting
    upstream render an empty page for a question this deployment cannot answer:

    * ``external`` -- CF_PROVIDER_SEARCH selected a provider;
    * ``native``   -- upstream Elasticsearch/SeaSearch is configured;
    * ``db-tags``  -- only the built-in tag backend answers: tag/creator
                      filtered queries work, plain full-text does not;
    * ``none``     -- nothing can answer.
    """
    from cloudfile_ext import providers
    if providers.selected(SEARCH):
        return 'external'
    if _native_search_available():
        return 'native'
    if _db_fallback_enabled() and _db_provider() is not None:
        return 'db-tags'
    return 'none'


def is_search_path_denied(username, repo_id, path):
    """Whether a directory ACL hides `path` for `username` in search/metadata.

    Called from seahub.search.utils.is_invisible_path so result sets honour
    directory-ACL ``invisible``/``none`` rules the same way directory listing
    does. The import is lazy so this module stays importable when the ACL
    capability is not installed; returns False when it is off.
    """
    from cloudfile_ext.acl import service
    return service.is_path_denied(username, repo_id, path)
