# -*- coding: utf-8 -*-
"""SMB/NFS external sources, browsable without entering the Seafile model.

Gated by CF_ENABLE_EXTERNAL_SOURCES. Spec: cloudfile-docker/docs/
external-sources.md.

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

    from django.urls import re_path

    from cloudfile_ext.external_sources import local_path
    from cloudfile_ext.external_sources.admin_apis import (
        AdminExternalSourceGrantsView, AdminExternalSourceView,
        AdminExternalSourcesView,
    )
    from cloudfile_ext.external_sources.apis import (
        ExternalSourceDirView, ExternalSourceFileView, ExternalSourcesView,
    )

    # One backend in this release, covering both SMB and NFS because the mount
    # is the operator's job. Registered by type rather than selected by a
    # CF_PROVIDER_* setting: local-path and a future smb backend coexist, each
    # serving the sources registered against it, so there is nothing to select.
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
    ])

    # No register_menu() yet: a menu entry pointing at a page that does not
    # exist is worse than no entry. It lands with the phase 2 frontend.
