"""Stable V2 auto-local key syntax shared by CloudFile allocation callers.

Matches cf_auto_key_valid() in cloudfile-server/common/cf-auto-storage.h.
The key names a managed subdirectory only; never accept absolute paths.
"""
import re

_KEY = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,78}[a-z0-9])?\Z")


def valid_repo_key(key):
    return isinstance(key, str) and bool(_KEY.fullmatch(key))
