"""Retired V1 metadata registration shim.

The supported V2 CE Tag batch lives at /api/v2.1/cloudfile/tags/batch/
and is mounted by seahub.urls using cloudfile_ext.v2.tag_http.TagBatch.
Never register the old FileTag endpoint or its separate ACL snapshot.
"""

def register(registry):
    # Compatibility with old registry callers only; no route is installed.
    return None
