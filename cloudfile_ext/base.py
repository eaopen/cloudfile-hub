# -*- coding: utf-8 -*-
"""Framework-level registrations that are not gated by a feature switch."""

from django.urls import path


def register(registry):
    from cloudfile_ext.views import CloudFileFeaturesView

    registry.register_urls([
        path('api/v2.1/cloudfile/features/', CloudFileFeaturesView.as_view(),
             name='cloudfile-features'),
    ])
