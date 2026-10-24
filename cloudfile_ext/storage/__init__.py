# -*- coding: utf-8 -*-
"""Storage-class assignment API (P2 storage backends).

Exposes storage allocation only for explicitly configured auto-local or
multi-class deployments, keeping native CE-only installations untouched. CloudFile
API endpoints.  No UI is implemented here (frontend work is deferred by design).

Spec: storage-backends.md.
"""


def register(registry):
    # Imported inside register() so that importing this package does not pull
    # in Django.
    from cloudfile_ext.features import is_enabled
    import os

    # Local V2 allocation uses the same RPC without an S3 dependency.
    # Existing CE installations with neither backend selected stay unchanged.
    if not (is_enabled('CF_ENABLE_S3_STORAGE') or
            os.environ.get('CF_LIBRARY_STORAGE') == 'auto'):
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
