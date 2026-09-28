# -*- coding: utf-8 -*-
"""Read-only local-directory external sources, browsable without entering the
Seafile model. v1 is scoped to local paths only: SMB/NFS, OpenList and every
other external form are normalized to a local directory on the host first, and
direct SMB support is cancelled by decision rather than deferred.

Gated by CF_ENABLE_EXTERNAL_SOURCES. Spec: cloudfile-docker/docs/
features/external-sources.md.

**External sources never enter the repo/commit/block model.** That is the
definition of the capability, not a first-release limitation, and every other
property follows from it: browse, single-file download, preview and (later)
indexed search work; the desktop sync client, WebDAV, zip download, history and
file locking are structurally impossible, because each of them is expressed in
commits, fs objects and blocks that an external file does not have.

Phase 1 -- what is here -- is everything independent of how sources are
presented: schema, provider contract, path containment, authorisation, and the
read API. Phase 2 adds CloudFile's own browser UI; phase 3 shadows the native
repo endpoints so sources appear in the ordinary library list. Both consume
exactly this, which is why the product decision between them could be deferred
at no cost (external-sources.md section six).
"""


def register(registry):
    # Imported inside register() so that importing this package does not pull
    # in Django: paths.py is the security boundary and has to stay runnable --
    # and mutation-testable -- on its own.
    from cloudfile_ext.features import is_enabled

    if not is_enabled('CF_ENABLE_EXTERNAL_SOURCES'):
        return

    from django.urls import path, re_path

    from cloudfile_ext.external_sources import local_path
    from cloudfile_ext.external_sources.admin_apis import (
        AdminExternalSourceGrantsView, AdminExternalSourceView,
        AdminExternalSourcesView,
    )
    from cloudfile_ext.external_sources.apis import (
        ExternalSourceDirView, ExternalSourceFileView, ExternalSourcesView,
    )
    from cloudfile_ext.external_sources.overlay_apis import ExternalOverlayView
    from cloudfile_ext.external_sources.search_apis import ExternalSourceSearchView
    from cloudfile_ext.external_sources.shadows import (
        ExternalApi2FileView, ExternalDirDetailView, ExternalDirView,
        ExternalFileDetailView, ExternalFileTagsView, ExternalFileView,
        ExternalRepoView, ExternalReposView, ExternalRepoTagsView,
    )
    from cloudfile_ext.external_sources.views import external_sources_page

    # One backend in this release, and the only one v1 will have: a local
    # directory. SMB/NFS/OpenList and everything else reach CloudFile already
    # mounted by the operator, so they need no backend here -- direct SMB was
    # cancelled by decision rather than deferred. Registered by type rather
    # than selected by a CF_PROVIDER_* setting because a source is answered by
    # exactly one backend, so there is nothing to select.
    local_path.register(registry)

    source_id = r'(?P<source_id>\d+)'

    registry.register_urls([
        re_path(r'^api/v2.1/cloudfile/external-sources/$',
                ExternalSourcesView.as_view(),
                name='cloudfile-external-sources'),
        re_path(r'^api/v2.1/cloudfile/external-sources/%s/dir/$' % source_id,
                ExternalSourceDirView.as_view(),
                name='cloudfile-external-source-dir'),
        re_path(r'^api/v2.1/cloudfile/external-sources/%s/file/$' % source_id,
                ExternalSourceFileView.as_view(),
                name='cloudfile-external-source-file'),

        re_path(r'^api/v2.1/admin/cloudfile/external-sources/$',
                AdminExternalSourcesView.as_view(),
                name='cloudfile-admin-external-sources'),
        re_path(r'^api/v2.1/admin/cloudfile/external-sources/%s/$' % source_id,
                AdminExternalSourceView.as_view(),
                name='cloudfile-admin-external-source'),
        re_path(r'^api/v2.1/admin/cloudfile/external-sources/%s/grants/$'
                % source_id,
                AdminExternalSourceGrantsView.as_view(),
                name='cloudfile-admin-external-source-grants'),
        re_path(r'^api/v2.1/cloudfile/external-sources/%s/overlay/$'
                % source_id, ExternalOverlayView.as_view(),
                name='cloudfile-external-source-overlay'),
        re_path(r'^api/v2.1/cloudfile/external-sources/search/$',
                ExternalSourceSearchView.as_view(),
                name='cloudfile-external-source-search'),
        path('cloudfile/external-sources/', external_sources_page,
             name='cloudfile-external-sources-page'),

        # Shadow the native read paths before Seahub sees a synthetic repo id.
        # Every class delegates unchanged ids straight back to upstream.
        path('api/v2.1/repos/', ExternalReposView.as_view(),
             name='cloudfile-external-shadow-repos'),
        re_path(r'^api/v2.1/repos/%s/$' % r'(?P<repo_id>[-0-9a-f]{36})',
                ExternalRepoView.as_view(), name='cloudfile-external-shadow-repo'),
        re_path(r'^api/v2.1/repos/%s/dir/$' % r'(?P<repo_id>[-0-9a-f]{36})',
                ExternalDirView.as_view(), name='cloudfile-external-shadow-dir'),
        re_path(r'^api/v2.1/repos/%s/file/$' % r'(?P<repo_id>[-0-9a-f]{36})',
                ExternalFileView.as_view(), name='cloudfile-external-shadow-file'),
        re_path(r'^api2/repos/%s/file/$' % r'(?P<repo_id>[-0-9a-f]{36})',
                ExternalApi2FileView.as_view(), name='cloudfile-external-shadow-api2-file'),
        re_path(r'^api2/repos/%s/file/detail/$' % r'(?P<repo_id>[-0-9a-f]{36})',
                ExternalFileDetailView.as_view(), name='cloudfile-external-shadow-file-detail'),
        # Three more native read paths the library view calls on an external
        # source. Upstream answers 404 for a synthetic repo id, and the
        # frontend surfaces two of those as error toasts (`repo-tags` on
        # every directory load, `file-tags` on preview), so each needs a
        # shadow that returns the native shape.
        re_path(r'^api/v2.1/repos/%s/repo-tags/$' % r'(?P<repo_id>[-0-9a-f]{36})',
                ExternalRepoTagsView.as_view(), name='cloudfile-external-shadow-repo-tags'),
        re_path(r'^api/v2.1/repos/%s/file-tags/$' % r'(?P<repo_id>[-0-9a-f]{36})',
                ExternalFileTagsView.as_view(), name='cloudfile-external-shadow-file-tags'),
        re_path(r'^api/v2.1/repos/%s/dir/detail/$' % r'(?P<repo_id>[-0-9a-f]{36})',
                ExternalDirDetailView.as_view(), name='cloudfile-external-shadow-dir-detail'),
    ])

    registry.register_menu({
        'key': 'external-sources',
        'label': 'External sources',
        'url': '/cloudfile/external-sources/',
        'feature': 'CF_ENABLE_EXTERNAL_SOURCES',
    })

    # SeaSearch owns its own index and offers no document-write protocol.
    # Run the mounted-tree scanner only when CloudFile owns the Meilisearch
    # index, so a harmless external source never starts a worker task in a
    # native search deployment.
    from django.conf import settings
    if getattr(settings, 'CF_PROVIDER_SEARCH', '') == 'meilisearch':
        from cloudfile_ext.external_sources.scanner import TASK_NAME, scan_tick
        registry.register_periodic_task(TASK_NAME, _scan_interval(), scan_tick)


def _scan_interval():
    import logging

    from django.conf import settings

    logger = logging.getLogger(__name__)
    try:
        return max(15, int(getattr(settings, 'CF_EXTERNAL_SCAN_INTERVAL', 60)))
    except (TypeError, ValueError):
        logger.warning('CF_EXTERNAL_SCAN_INTERVAL is not a number; using 60s')
        return 60
