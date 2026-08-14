# -*- coding: utf-8 -*-
"""Small adapters around the pure action policy and local-software protocol."""

import os
import json
import uuid
import time
import hashlib
import secrets
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


def _agent_session_ttl():
    # A ticket is only for claim. It is deliberately shorter than the
    # post-claim content/write-back capabilities minted by the Hub.
    return min(60, max(30, int(getattr(settings, 'CF_LOCAL_APP_SESSION_TTL', 60))))


def _session_alias():
    return getattr(settings, 'CF_DATABASE_ALIAS', 'cloudfile')


def _ticket_digest(ticket):
    return hashlib.sha256(ticket.encode('utf-8')).hexdigest()


def _agent_session_descriptor(mode, path, ticket, ttl, now):
    """Return only browser-safe claim data; never expose content capability URLs."""
    return {
        'protocol': 'cloudfile-local/v2',
        'mode': mode,
        'file': {'name': os.path.basename(path)},
        'ticket': ticket,
        'expires_in': ttl,
        'expires_at': now + ttl,
    }


def _issue_agent_session(mode, repo_id, path, username, file_id='', generation=''):
    now = int(time.time())
    ttl = _agent_session_ttl()
    session_id = str(uuid.uuid4())
    ticket = secrets.token_urlsafe(32)
    alias = _session_alias()
    with connections[alias].cursor() as cursor:
        cursor.execute(
            'INSERT INTO cf_edit_session '
            '(session_id, ticket_digest, ticket_expire_at, mode, username, repo_id, '
            'normalized_path, base_file_id, generation, state, created_at, updated_at) '
            'VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)',
            [session_id, _ticket_digest(ticket), now + ttl, mode, username, repo_id,
             path, file_id or None, generation or None, 'created', now, now])
    return _agent_session_descriptor(mode, path, ticket, ttl, now)


def issue_local_view_session(repo_id, path, username):
    """Create an opaque one-time local-view ticket, never a URL capability."""
    return _issue_agent_session('local-view', repo_id, path, username)


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

    try:
        session = _issue_agent_session(
            'local-edit', repo_id, path, username, file_id, lock['generation'])
    except Exception:
        # A lease without a claimable session is a denial-of-service lock.
        release_checkout(repo_id, path, username, lock['generation'])
        return {'ok': False, 'reason': 'session_store_unavailable'}
    session['ok'] = True
    return session


def _read_session(session_id):
    alias = _session_alias()
    with connections[alias].cursor() as cursor:
        cursor.execute(
            'SELECT session_id, mode, username, repo_id, normalized_path, '
            'base_file_id, generation, state, ticket_expire_at '
            'FROM cf_edit_session WHERE session_id = %s', [session_id])
        row = cursor.fetchone()
    if not row:
        return None
    return dict(zip((
        'session_id', 'mode', 'username', 'repo_id', 'path', 'base_file_id',
        'generation', 'state', 'ticket_expire_at'), row))


def claim_agent_session(ticket, server_origin):
    """Atomically exchange a browser-visible ticket for agent-only URLs."""
    from django.db import transaction

    now = int(time.time())
    alias = _session_alias()
    digest = _ticket_digest(ticket)
    with transaction.atomic(using=alias):
        with connections[alias].cursor() as cursor:
            cursor.execute(
                'SELECT session_id, mode, username, repo_id, normalized_path, '
                'base_file_id, generation, ticket_expire_at '
                'FROM cf_edit_session WHERE ticket_digest = %s AND state = %s '
                'FOR UPDATE', [digest, 'created'])
            row = cursor.fetchone()
            if not row or row[7] <= now:
                return None
            cursor.execute(
                'UPDATE cf_edit_session SET state = %s, claimed_at = %s, '
                'updated_at = %s WHERE session_id = %s AND state = %s',
                ['claimed', now, now, row[0], 'created'])
    session_id, mode, username, repo_id, path, base_file_id, generation, expires_at = row
    if mode == 'local-edit':
        lock = _lock_rpc('cf_lock_status', {'repo_id': repo_id, 'path': path})
        if not lock.get('locked') or lock.get('owner') != username \
                or lock.get('kind') != 'local-edit' or lock.get('generation') != generation:
            with connections[alias].cursor() as cursor:
                cursor.execute(
                    'UPDATE cf_edit_session SET state = %s, closed_at = %s, updated_at = %s '
                    'WHERE session_id = %s AND state = %s',
                    ['aborted', now, now, session_id, 'claimed'])
            release_checkout(repo_id, path, username, generation)
            return None
    # Ticket expiry is intentionally one minute; claimed local-edit sessions
    # use the C lease duration and must not inherit that short claim window.
    capability_ttl = 30 * 60 if mode == 'local-edit' else 5 * 60
    content_token = uuid.uuid4().hex
    cache.set('thirdparty_editor_access_token_' + content_token, {
        'request_user': username,
        'repo_id': repo_id,
        'file_path': path,
        'permission': {'can_edit': False},
    }, capability_ttl)
    content_url = server_origin.rstrip('/') + _join_site(
        'thirdparty-editor/file-content/?access_token=' + quote(content_token, safe=''))
    response = {
        'session_id': session_id,
        'mode': mode,
        'expires_at': now + capability_ttl,
        'file': {'name': os.path.basename(path), 'content_url': content_url},
    }
    if mode == 'local-edit':
        capability = secrets.token_urlsafe(32)
        cache.set('cloudfile_local_writeback_' + capability, session_id, capability_ttl)
        response['writeback'] = {
            'content_url': server_origin.rstrip('/') + _join_site(
                'api/v2.1/cloudfile/agent-sessions/%s/content/' % session_id),
            'heartbeat_url': server_origin.rstrip('/') + _join_site(
                'api/v2.1/cloudfile/agent-sessions/%s/heartbeat/' % session_id),
            'capability': capability,
        }
    return response


def local_edit_session(session_id, capability):
    if not capability or cache.get('cloudfile_local_writeback_' + capability) != session_id:
        return None
    session = _read_session(session_id)
    if not session or session['mode'] != 'local-edit' or session['state'] != 'claimed':
        return None
    return session


def refresh_local_edit_session(session_id, capability):
    session = local_edit_session(session_id, capability)
    if not session:
        return None
    result = refresh_lock(
        session['repo_id'], session['path'], session['username'],
        session['generation'], lease_seconds=30 * 60)
    if not result.get('ok'):
        return None
    # Keep the agent capability no longer than the renewed lock lease.
    cache.set('cloudfile_local_writeback_' + capability, session_id, 30 * 60)
    return result


def consume_local_edit_session(session_id):
    now = int(time.time())
    alias = _session_alias()
    with connections[alias].cursor() as cursor:
        cursor.execute(
            'UPDATE cf_edit_session SET state = %s, closed_at = %s, updated_at = %s '
            'WHERE session_id = %s AND state = %s',
            ['closed', now, now, session_id, 'claimed'])


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


def refresh_lock(repo_id, path, username, generation,
                 lease_seconds=12 * 60 * 60):
    """Renew an owned lease without extending its hard-expiry fence."""
    return _lock_rpc('cf_lock_refresh', {
        'repo_id': repo_id,
        'path': path,
        'owner': username,
        'generation': generation,
        'lease_seconds': lease_seconds,
    })


def release_checkout(repo_id, path, username, generation=''):
    payload = {'repo_id': repo_id, 'path': path, 'owner': username}
    if generation:
        payload['generation'] = generation
    return _lock_rpc('cf_lock_release', payload)


def force_release_lock(repo_id, path, actor, generation, reason=''):
    """Release exactly the generation an administrator reviewed."""
    payload = {
        'repo_id': repo_id,
        'path': path,
        'actor': actor,
        'generation': generation,
    }
    if reason:
        payload['reason'] = reason
    return _lock_rpc('cf_lock_force_release', payload)
