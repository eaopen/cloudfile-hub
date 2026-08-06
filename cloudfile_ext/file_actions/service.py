# -*- coding: utf-8 -*-
"""Small adapters around the pure action policy and local-software protocol."""

import os
import json
import uuid
import time
from urllib.parse import quote

from django.conf import settings
from django.core.cache import cache
from django.db import connections

from cloudfile_ext.features import enabled_features
from cloudfile_ext.file_actions.policy import actions_for, native_lock_request


def _site_root():
    return getattr(settings, 'SITE_ROOT', '/') or '/'


def _join_site(path):
    return _site_root().rstrip('/') + '/' + path.lstrip('/')


def native_preview_url(repo_id, path):
    """Return the upstream authenticated file view URL for one path."""
    return _join_site('lib/%s/file%s' % (repo_id, quote(path, safe='/')))


def _lock_rpc(method, payload):
    """Call the CE-specific C lock backend without a Hub-side fallback."""
    from seaserv import seafile_api

    try:
        response = getattr(seafile_api, method)(json.dumps(payload))
        return json.loads(response or '{}')
    except Exception:
        return {'ok': False, 'reason': 'unavailable'}


def lock_provider_ready(repo_id, path):
    """Ask the authority that sync and WebDAV write paths consult.

    A feature flag cannot prove that an upgraded server has the corresponding
    C provider loaded.  The status RPC therefore gates write actions and an
    unavailable/older server leaves them disabled rather than fail-open.
    """
    response = _lock_rpc('cf_lock_status', {'repo_id': repo_id, 'path': path})
    return response.get('ok') is True


def lock_status(repo_id, path, username=''):
    """Return normalized lease state for the native Hub lock controls."""
    result = _lock_rpc('cf_lock_status', {'repo_id': repo_id, 'path': path})
    if result.get('ok') is not True:
        return result
    owner = result.get('owner', '')
    result['locked_by_me'] = bool(result.get('locked') and username and owner == username)
    return result


def lock_status_map(repo_id, paths, username=''):
    """Read live list-view lock state in one query from the authority table."""
    paths = tuple(dict.fromkeys(paths))
    if not paths:
        return {}
    alias = getattr(settings, 'CF_DATABASE_ALIAS', 'cloudfile')
    placeholders = ', '.join(['%s'] * len(paths))
    now = int(time.time())
    query = (
        'SELECT normalized_path, owner, kind, lease_until '
        'FROM cf_lock_lease WHERE repo_id = %s AND status = %s '
        'AND lease_until > %s AND hard_expire_at > %s '
        'AND normalized_path IN (' + placeholders + ')'
    )
    with connections[alias].cursor() as cursor:
        cursor.execute(query, [repo_id, 'active', now, now] + list(paths))
        rows = cursor.fetchall()
    return {
        row[0]: {
            'is_locked': True,
            'owner': row[1],
            'kind': row[2],
            'lease_until': row[3],
            'locked_by_me': bool(username and row[1] == username),
        }
        for row in rows
    }


def lock_file(repo_id, path, username, lease_seconds=12 * 60 * 60):
    """Acquire the same authoritative lease enforced by all write paths."""
    current = lock_status(repo_id, path, username)
    if current.get('ok') and current.get('locked_by_me'):
        # Retrying after a lost HTTP response must not turn an already-owned
        # lock into a 423 conflict.
        return current
    request = native_lock_request(repo_id, path, username)
    request['lease_seconds'] = lease_seconds
    return _lock_rpc('cf_lock_acquire', request)


def get_actions(repo_id, path, can_edit=False):
    features = enabled_features()
    actions = actions_for(
        path, features,
        getattr(settings, 'CF_FILE_ACTION_PREVIEW_EXTENSIONS', ()),
        lock_provider_ready=lock_provider_ready(repo_id, path),
        can_edit=can_edit,
    )
    for action in actions:
        if action['id'] == 'native-preview' and action['available']:
            action['url'] = native_preview_url(repo_id, path)
    return actions


def _local_software_session(mode, ttl, file_name, content_url, commit_url='', generation=''):
    """Build the versioned descriptor consumed by portable and installed agents."""
    session = {
        'protocol': 'cloudfile-local/v1',
        'mode': mode,
        'expires_in': ttl,
        'file': {
            'name': file_name,
            'content_url': content_url,
        },
    }
    if commit_url:
        session['writeback'] = {
            'content_url': commit_url,
            'generation': generation,
        }
    return session


def issue_local_view_session(repo_id, path, username):
    """Create a one-file read capability consumed by a local Agent.

    `thirdparty_editor_access_token_*` is already the hardened upstream
    gateway for an untrusted editor process: it checks expiry, library and
    file existence before returning bytes.  CloudFile narrows its lifetime to
    five minutes and grants `can_edit=False` unconditionally.
    """
    token = uuid.uuid4().hex
    ttl = max(30, int(getattr(settings, 'CF_LOCAL_APP_SESSION_TTL', 300)))
    cache.set('thirdparty_editor_access_token_' + token, {
        'request_user': username,
        'repo_id': repo_id,
        'file_path': path,
        'permission': {'can_edit': False},
    }, ttl)
    query = '?access_token=' + quote(token, safe='')
    return _local_software_session(
        'local-view', ttl, os.path.basename(path),
        _join_site('thirdparty-editor/file-content/' + query))


def issue_local_edit_session(repo_id, path, username, file_id):
    """Issue a short-lived agent capability backed by a C lease and fencing."""
    lock = _lock_rpc('cf_lock_acquire', {
        'repo_id': repo_id,
        'path': path,
        'owner': username,
        'kind': 'local-edit',
        'lease_seconds': 30 * 60,
        'hard_expire_seconds': 24 * 60 * 60,
    })
    if not lock.get('ok'):
        return lock

    token = uuid.uuid4().hex
    ttl = max(30, int(getattr(settings, 'CF_LOCAL_APP_SESSION_TTL', 300)))
    cache.set('thirdparty_editor_access_token_' + token, {
        'request_user': username,
        'repo_id': repo_id,
        'file_path': path,
        'permission': {'can_edit': False},
    }, ttl)
    cache.set('cloudfile_local_edit_session_' + token, {
        'repo_id': repo_id,
        'path': path,
        'username': username,
        'base_file_id': file_id,
        'generation': lock['generation'],
    }, ttl)
    query = '?access_token=' + quote(token, safe='')
    session = _local_software_session(
        'local-edit', ttl, os.path.basename(path),
        _join_site('thirdparty-editor/file-content/' + query),
        _join_site('api/v2.1/cloudfile/agent-sessions/%s/content/' % token),
        lock['generation'])
    session['ok'] = True
    return session


def local_edit_session(token):
    return cache.get('cloudfile_local_edit_session_' + token)


def consume_local_edit_session(token):
    cache.delete('cloudfile_local_edit_session_' + token)
    cache.delete('thirdparty_editor_access_token_' + token)


def checkout(repo_id, path, username, source):
    """Create the authoritative lease used by manual and programmatic checkout."""
    return _lock_rpc('cf_lock_acquire', {
        'repo_id': repo_id,
        'path': path,
        'owner': username,
        'kind': 'checkout',
        'lease_seconds': 12 * 60 * 60,
        'hard_expire_seconds': 72 * 60 * 60,
        'source': source,
    })


def release_checkout(repo_id, path, username, generation=''):
    payload = {'repo_id': repo_id, 'path': path, 'owner': username}
    if generation:
        payload['generation'] = generation
    return _lock_rpc('cf_lock_release', payload)
