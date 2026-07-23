# -*- coding: utf-8 -*-
"""SSO login plus user/organisation mapping. Phase P1 -- not implemented yet.

Gated by CF_ENABLE_SSO. When built, this registers an authentication backend
via EXTRA_AUTHENTICATION_BACKENDS and its callback routes via
registry.register_urls().
"""


def register(registry):
    from cloudfile_ext.features import is_enabled

    if not is_enabled("CF_ENABLE_SSO"):
        return
