# -*- coding: utf-8 -*-
"""Small adapters around the pure action policy and local-software protocol."""

import os
import uuid
import time
import hashlib
import secrets
from urllib.parse import quote

from django.conf import settings
from django.core.cache import cache
from django.db import connections

from cloudfile_ext.features import enabled_features
from cloudfile_ext.file_actions.policy import actions_for


#: CloudFile's own write-lifecycle error code, mirroring common/cf-fileop.h.
CF_ERR_FILE_LOCKED = 600


def searpc_lock_status(error):
    """Map a SearpcError carrying CF_ERR_FILE_LOCKED to HTTP 423, else None.

    The C write lifecycle refuses with ``CF_ERR_FILE_LOCKED`` (600) and the
    fork's ``seafile.rpcclient`` preserves that code on ``SearpcError``. REST
    and WebDAV entry points call this so a locked file reads as 423 Locked
    rather than a generic 500 -- the upstream behaviour of dropping err_code.
    """
    if getattr(error, 'code', None) == CF_ERR_FILE_LOCKED:
        return 423
    return None


def _site_root():
    return getattr(settings, 'SITE_ROOT', '/') or '/'


def _join_site(path):
    return _site_root().rstrip('/') + '/' + path.lstrip('/')


def native_preview_url(repo_id, path):
    """Return the upstream authenticated file view URL for one path."""
    return _join_site('lib/%s/file%s' % (repo_id, quote(path, safe='/')))




def lock_provider_ready(repo_id, path):
    """No public editing assembler is enabled until native publication is ready."""
    return False


def lock_status_map(repo_id, paths, username=''):
    """Read live list-view lock state in one query from the authority table."""
    paths = tuple(dict.fromkeys(paths))
    if not paths:
        return {}
    alias = getattr(settings, 'CF_DATABASE_ALIAS', 'cloudfile')
    placeholders = ', '.join(['%s'] * len(paths))
    query = (
        'SELECT r.path, g.owner_native_user, g.mode, g.lease_until '
        'FROM cf_resource r JOIN cf_edit_guard g ON g.resource_uid=r.uid '
        'WHERE r.repo_id = %s AND r.state = %s AND g.guard_id IS NOT NULL '
        'AND r.path IN (' + placeholders + ')'
    )
    with connections[alias].cursor() as cursor:
        cursor.execute(query, [repo_id, 'active'] + list(paths))
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


def _agent_session_descriptor(mode, repo_id, path, ticket, ttl, now,
                              file_id='', size=0, mtime=0):
    """Return only browser-safe claim data; never expose content capability URLs.

    repo_id / path / file_id / size / mtime are included so the web page can
    query the local agent's cached copy (existence + size/mtime) and render a
    "which is newer / larger" conflict dialog before dispatching a session.
    file_id is the Seafile object ID (obj_id) -- a content-addressed version
    fingerprint: it changes whenever file content changes, and stays stable
    otherwise. The web page compares it against the file_id it recorded when
    the file was last downloaded (NOT against a raw content SHA1, which is a
    different hash space).
    """
    return {
        'protocol': 'cloudfile-local/v2',
        'mode': mode,
        'repo_id': repo_id,
        'path': path,
        'file': {'name': os.path.basename(path)},
        'file_id': file_id or '',
        'size': size or 0,
        'mtime': mtime or 0,
        'ticket': ticket,
        'expires_in': ttl,
        'expires_at': now + ttl,
    }


def _issue_agent_session(mode, repo_id, path, username, generation=''):
    now = int(time.time())
    ttl = _agent_session_ttl()
    session_id = str(uuid.uuid4())
    ticket = secrets.token_urlsafe(32)
    # Content identity + size + mtime drive the local-cache reuse / conflict
    # decision on the client. file_id is the Seafile object ID (obj_id) -- a
    # content-addressed version fingerprint (it is the SHA1 of the file's
    # metadata JSON object, not of the raw file bytes), so the client compares
    # it against the file_id recorded at download time, never against a raw
    # content SHA1.
    from seaserv import seafile_api
    dirent = seafile_api.get_dirent_by_path(repo_id, path)
    file_id = getattr(dirent, 'obj_id', '') or ''
    size = getattr(dirent, 'size', 0) or 0
    mtime = getattr(dirent, 'mtime', 0) or 0
    alias = _session_alias()
    with connections[alias].cursor() as cursor:
        cursor.execute(
            'INSERT INTO cf_edit_session '
            '(session_id, ticket_digest, ticket_expire_at, mode, username, repo_id, '
            'normalized_path, base_file_id, generation, state, created_at, updated_at) '
            'VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)',
            [session_id, _ticket_digest(ticket), now + ttl, mode, username, repo_id,
             path, file_id or None, generation or None, 'created', now, now])
    return _agent_session_descriptor(mode, repo_id, path, ticket, ttl, now,
                                     file_id, size, mtime)


def issue_local_view_session(repo_id, path, username):
    """Create an opaque one-time local-view ticket, never a URL capability."""
    return _issue_agent_session('local-view', repo_id, path, username)


def issue_local_edit_session(repo_id, path, username):
    """Issue a lock-free local-edit session.

    The file is downloaded to the agent's mirror directory, edited locally,
    then uploaded manually by the user through the normal web upload path.
    No C lease is taken, so the server file stays editable by others.
    """
    return _issue_agent_session('local-edit', repo_id, path, username)




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
    if mode not in ('local-view', 'local-edit'):
        return None
    capability_ttl = 5 * 60
    content_token = uuid.uuid4().hex
    cache.set('thirdparty_editor_access_token_' + content_token, {
        'request_user': username,
        'repo_id': repo_id,
        'file_path': path,
        'permission': {'can_edit': False},
    }, capability_ttl)
    content_url = server_origin.rstrip('/') + _join_site(
        'thirdparty-editor/file-content/?access_token=' + quote(content_token, safe=''))
    # Re-read the dirent for size/mtime so the client can render the conflict
    # dialog accurately even if the dirent changed since the ticket was issued.
    from seaserv import seafile_api
    dirent = seafile_api.get_dirent_by_path(repo_id, path)
    file_id = getattr(dirent, 'obj_id', '') or base_file_id or ''
    size = getattr(dirent, 'size', 0) or 0
    mtime = getattr(dirent, 'mtime', 0) or 0
    response = {
        'session_id': session_id,
        'mode': mode,
        'expires_at': now + capability_ttl,
        'repo_id': repo_id,
        'path': path,
        'file': {'name': os.path.basename(path), 'content_url': content_url},
        'file_id': file_id,
        'size': size,
        'mtime': mtime,
    }
    return response
