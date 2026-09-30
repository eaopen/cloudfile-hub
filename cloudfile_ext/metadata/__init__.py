# -*- coding: utf-8 -*-
"""Register legacy FileTag batch reads without changing other tag models."""


def register(registry):
    from cloudfile_ext.features import is_enabled

    if not (is_enabled("CF_ENABLE_METADATA") or is_enabled("CF_ENABLE_TAGS")):
        return

    if is_enabled("CF_ENABLE_TAGS"):
        from django.urls import path
        from cloudfile_ext.legacy_tags.views import LegacyFileTagsBatch
        # Reuse the existing tags switch; no upstream endpoint or schema patch.
        registry.register_urls([path('api/v2.1/cloudfile/legacy-file-tags/batch/',
            LegacyFileTagsBatch.as_view(), name='cloudfile-legacy-file-tags-batch')])
