# -*- coding: utf-8 -*-
"""Unified, permission-aware entry points for opening one file.

This package deliberately owns *selection*, not rendering: native Seafile CE
continues to render normal previews.  Keeping the decision in one small
capability stops a new client (OnlyOffice, Native Messaging, a future CAD
viewer) from independently guessing which action is safe for a file.
"""


def register(registry):
    from cloudfile_ext.features import is_enabled

    enabled = any(is_enabled(name) for name in (
        'CF_ENABLE_FILE_PREVIEW', 'CF_ENABLE_CHECKOUT', 'CF_ENABLE_LOCAL_APP',
    ))
    if not enabled:
        return

    from django.urls import path, re_path

    from cloudfile_ext.file_actions.apis import (
        AgentContentView, CheckoutView, FileActionsPageView, FileActionsView,
        LocalSessionView,
    )

    repo_id = r'(?P<repo_id>[-0-9a-f]{36})'
    registry.register_urls([
        re_path(r'^api/v2.1/cloudfile/repos/%s/file-actions/$' % repo_id,
                FileActionsView.as_view(), name='cloudfile-file-actions'),
        re_path(r'^api/v2.1/cloudfile/repos/%s/local-sessions/$' % repo_id,
                LocalSessionView.as_view(), name='cloudfile-local-session'),
        re_path(r'^api/v2.1/cloudfile/agent-sessions/(?P<token>[0-9a-f]{32})/content/$',
                AgentContentView.as_view(), name='cloudfile-agent-content'),
        re_path(r'^api/v2.1/cloudfile/repos/%s/checkout/$' % repo_id,
                CheckoutView.as_view(), name='cloudfile-checkout'),
        path('cloudfile/file-actions/', FileActionsPageView.as_view(),
             name='cloudfile-file-actions-page'),
    ])
