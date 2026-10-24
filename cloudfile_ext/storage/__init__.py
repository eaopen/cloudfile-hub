# -*- coding: utf-8 -*-
"""Thin CloudFile storage allocation API over the existing native Server RPC.

The native get_storage_classes / create_repo_with_storage RPCs are the only
storage capability authority. No second Hub-side seafile.conf or env parser.
Ordinary Seafile repository APIs stay unchanged.
"""


def register(registry):
    # URL registration is inert: when neither V2 local nor storage classes
    # are configured the Server returns [] and rejects allocation.
    from django.urls import re_path
    from cloudfile_ext.storage.views import RepoWithStorageView, StorageClassesView

    registry.register_urls([
        re_path(r'^api/v2.1/cloudfile/storage-classes/$',
                StorageClassesView.as_view(),
                name='cloudfile-storage-classes'),
        re_path(r'^api/v2.1/cloudfile/repos/$',
                RepoWithStorageView.as_view(),
                name='cloudfile-repos-with-storage'),
    ])
