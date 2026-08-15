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
    return bool(providers.selected(SEARCH))


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
            # Native search cannot express these, so falling through to
            # Elasticsearch would answer a different question than the one
            # asked. Same reasoning as UnsupportedFilter.
            raise search_query.UnsupportedFilter(
                'structured filters require a CloudFile search provider; '
                'none is selected (CF_PROVIDER_SEARCH)')
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


def is_search_path_denied(username, repo_id, path):
    """Whether a directory ACL hides `path` for `username` in search/metadata.

    Called from seahub.search.utils.is_invisible_path so result sets honour
    directory-ACL ``invisible``/``none`` rules the same way directory listing
    does. The import is lazy so this module stays importable when the ACL
    capability is not installed; returns False when it is off.
    """
    from cloudfile_ext.acl import service
    return service.is_path_denied(username, repo_id, path)
