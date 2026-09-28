# -*- coding: utf-8 -*-
"""Storage-class assignment API (P2 storage backends).

Exposes the two backend pieces the self-service allocation UI needs -- list
the configured storage classes, and create a repo pinned to one -- as CloudFile
API endpoints.  No UI is implemented here (frontend work is deferred by design).

Spec: cloudfile-docker/docs/features/storage-backends.md.
"""


def register(registry):
    # Imported inside register() so that importing this package does not pull
    # in Django.
    from cloudfile_ext.features import is_enabled

    if not is_enabled('CF_ENABLE_S3_STORAGE'):
        return

    from django.urls import re_path

    from cloudfile_ext.storage.views import (
        RepoWithStorageView, StorageClassesView,
    )

    registry.register_urls([
        re_path(r'^api/v2.1/cloudfile/storage-classes/$',
                StorageClassesView.as_view(),
                name='cloudfile-storage-classes'),
        re_path(r'^api/v2.1/cloudfile/repos/$',
                RepoWithStorageView.as_view(),
                name='cloudfile-repos-with-storage'),
    ])
