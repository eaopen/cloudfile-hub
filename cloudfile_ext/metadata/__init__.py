# -*- coding: utf-8 -*-
"""File properties and tags. Phase P2 -- not implemented yet.

Gated by CF_ENABLE_METADATA and CF_ENABLE_TAGS. Metadata has to survive move
and rename, so it will hang off a post file-op hook rather than off paths.
"""


def register(registry):
    from cloudfile_ext.features import is_enabled

    if not (is_enabled("CF_ENABLE_METADATA") or is_enabled("CF_ENABLE_TAGS")):
        return
