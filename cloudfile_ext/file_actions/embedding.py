"""Minimal trusted repo-root embedding contract (v0.4, no SDK, no VFS)."""

import re
from urllib.parse import quote

_REPO_ID = re.compile(r'^[0-9a-fA-F-]{36}$')
_KEY = re.compile(r'^[A-Za-z0-9._-]{1,80}$')


def configured_repo(resource_map, resource_key):
    """Resolve *only* server-owned mappings; never accept client paths."""
    if not isinstance(resource_key, str) or not _KEY.fullmatch(resource_key):
        return None
    config = resource_map.get(resource_key) if isinstance(resource_map, dict) else None
    if not isinstance(config, dict) or not _REPO_ID.fullmatch(
            str(config.get('repo_id', ''))):
        return None
    # The standard CE UI cannot enforce an arbitrary subtree boundary.
    # v0.4 MVP embeds a whole authorized repository, nothing broader.
    if config.get('root_path', '/') != '/':
        return None
    return str(config['repo_id'])


def library_entry(site_root, repo_id, repo_name):
    if not _REPO_ID.fullmatch(repo_id):
        raise ValueError('Invalid repository')
    return (site_root.rstrip('/') + '/library/' + repo_id + '/' +
            quote(repo_name, safe='') + '/')
