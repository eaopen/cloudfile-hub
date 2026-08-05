# -*- coding: utf-8 -*-
"""OnlyOffice callback guard.

The CE renderer and document configuration stay upstream-owned.  CloudFile
shadows just the callback URL to authenticate Document Server and make a retry
of a completed save idempotent. When the C lock provider is live,
file_actions creates the shared OnlyOffice lease before opening the renderer.
"""


def register(registry):
    from cloudfile_ext.features import is_enabled

    if not is_enabled("CF_ENABLE_ONLYOFFICE"):
        return

    from django.urls import path
    from cloudfile_ext.office.callbacks import onlyoffice_callback

    registry.register_urls([
        path('onlyoffice/editor-callback/', onlyoffice_callback,
             name='onlyoffice_editor_callback'),
    ])
