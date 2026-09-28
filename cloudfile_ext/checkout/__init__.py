# -*- coding: utf-8 -*-
"""File locking and check-in/check-out. Phase P3 -- not implemented yet.

Gated by CF_ENABLE_CHECKOUT. Locks need a server-side enforcement point
alongside the ACL one, plus a timeout path for abandoned checkouts.
First phase covers Seafile primary storage only.
"""


def register(registry):
    from cloudfile_ext.features import is_enabled

    if not is_enabled("CF_ENABLE_CHECKOUT"):
        return
