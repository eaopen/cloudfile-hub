# -*- coding: utf-8 -*-
"""SMB/NFS external sources mounted as virtual directories.
Phase P4 -- not implemented yet.

Gated by CF_ENABLE_EXTERNAL_SOURCES. External sources deliberately stay out of
the Seafile repo/commit/block model: each mount declares its capabilities
(preview/search/metadata but not collaborative edit, checkout, file lock,
versioning or sync client) and the first release is read-only.
"""


def register(registry):
    from cloudfile_ext.features import is_enabled

    if not is_enabled("CF_ENABLE_EXTERNAL_SOURCES"):
        return
