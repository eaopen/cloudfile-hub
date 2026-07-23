# -*- coding: utf-8 -*-
"""OnlyOffice editing and callbacks. Phase P3 -- not implemented yet.

Gated by CF_ENABLE_ONLYOFFICE. Callbacks must be idempotent: OnlyOffice
retries them, and a non-idempotent handler corrupts document history.
"""


def register(registry):
    from cloudfile_ext.features import is_enabled

    if not is_enabled("CF_ENABLE_ONLYOFFICE"):
        return
