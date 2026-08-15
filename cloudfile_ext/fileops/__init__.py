# -*- coding: utf-8 -*-
"""Unified copy/move precheck, permission-change warning, idempotency and
failure reporting (P2-06).

Shadows the native ``/api2/repos/{repo}/fileops/{copy,move}/`` endpoints when
``CF_ENABLE_FILEOPS`` is on, and leaves them entirely to upstream when off.
The permission model is CE's ``r``/``rw``/``admin`` (see cloudfile-docker/
docs/roles-semantics.md); no five-level role is introduced.

Spec: cloudfile-docker/docs/features/fileops.md. The pure decision logic is in
``policy.py``, which is Django-free so it shares the same test discipline as the
ACL and fileop case sets.
"""


def register(registry):
    # Imported inside register() so that importing this package does not pull
    # in Django: policy.py is the security boundary and has to stay runnable on
    # its own.
    from cloudfile_ext.features import is_enabled

    if not is_enabled('CF_ENABLE_FILEOPS'):
        return

    from django.urls import re_path

    from cloudfile_ext.fileops.views import FileopsCopyView, FileopsMoveView

    repo_id = r'(?P<repo_id>[-0-9a-f]{36})'

    registry.register_urls([
        re_path(r'^api2/repos/%s/fileops/copy/$' % repo_id,
                FileopsCopyView.as_view(), name='cloudfile-fileops-copy'),
        re_path(r'^api2/repos/%s/fileops/move/$' % repo_id,
                FileopsMoveView.as_view(), name='cloudfile-fileops-move'),
    ])
