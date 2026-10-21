# -*- coding: utf-8 -*-
"""Small adapters around the pure action policy and local-software protocol."""

import os
import base64
from urllib.parse import urlsplit, urlencode
import hashlib
from urllib.parse import quote

from django.conf import settings
from django.db import connections

from cloudfile_ext.features import enabled_features
from cloudfile_ext.file_actions.policy import actions_for, extension


# A small default preference, not a second copy of eap-fileview's FileType.
# Seafile's native PDF/text/image/media readers stay primary; eap-fileview
# handles formats that benefit from conversion or special parsers.
NATIVE_FIRST_PREVIEW = frozenset((
    'pdf', 'txt', 'log', 'md', 'markdown', 'json', 'xml', 'html', 'htm', 'csv', 'tsv',
    'py', 'js', 'css', 'java', 'c', 'cpp', 'yaml', 'yml',
    'jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'bmp', 'mp3', 'mp4', 'webm',
))
EXTERNAL_PREVIEW_EXTENSIONS = frozenset((
    'xmind', 'eml', 'msg', 'drawio', 'bpmn', 'epub', 'ofd',
    'dwg', 'dxf', 'dwf', 'dwt', 'stl', 'step', 'stp', 'iges', 'igs',
    'ifc', 'gltf', 'glb', 'obj', '3ds', 'fbx', 'ply', 'tif', 'tiff',
    'zip', '7z', 'rar', 'doc', 'docx', 'ppt', 'pptx', 'xls', 'xlsx',
    'odt', 'ods', 'odp', 'wps', 'et', 'dps', 'vsd', 'vsdx',
    'psd', 'csv', 'txt', 'md', 'pdf', 'jpg', 'jpeg', 'png',
    'docm', 'xlsm', 'pptm', 'rtf', 'dot', 'dotx', 'dotm',
    'xlt', 'xltx', 'xltm', 'pages', 'fodt', 'fods',
))
OFFICE_DOCUMENT_EXTENSIONS = frozenset((
    'doc', 'docx', 'ppt', 'pptx', 'xls', 'xlsx', 'odt', 'ods', 'odp',
    'wps', 'et', 'dps', 'vsd', 'vsdx', 'rtf', 'pages',
    'docm', 'xlsm', 'pptm', 'dot', 'dotx', 'dotm',
    'xlt', 'xltx', 'xltm', 'fodt', 'fods',
))


def choose_preview_provider(ext, *, native_available, external_available):
    """Select simple native rendering or conversion-based preview, never OnlyOffice.

    'native_available' must mean a self-contained Seafile preview handler;
    upstream Office routes backed by OnlyOffice do not qualify.
    """
    if native_available and ext in NATIVE_FIRST_PREVIEW:
        return 'native'
    if external_available:
        return 'external'
    if native_available:
        return 'native'
    return None


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





def external_preview_enabled():
    """An unconfigured viewer cannot replace working native Seafile preview."""
    base = getattr(settings, 'CF_PREVIEW_PUBLIC_URL', '').strip()
    provider = getattr(settings, 'CF_PREVIEW_PROVIDER', 'eap-fileview')
    if provider != 'eap-fileview' or not base:
        return False
    parsed = urlsplit(base)
    # HTTP is permitted for private development only; operators must secure
    # the origin and fileserver reachability before internet-facing rollout.
    return parsed.scheme in ('https', 'http') and bool(parsed.netloc) and not (
        parsed.username or parsed.password or parsed.query or parsed.fragment)


def external_preview_url(repo_id, path, username):
    """Issue a normal Seafile read token AFTER the calling view checks live ACL."""
    if not external_preview_enabled():
        raise ValueError('External preview is not configured')
    from seaserv import seafile_api
    file_id = seafile_api.get_file_id_by_path(repo_id, path)
    if not file_id:
        raise ValueError('File no longer exists')
    token = seafile_api.get_fileserver_access_token(
        repo_id, file_id, 'download', username, use_onetime=False)
    if not token:
        raise ValueError('Read token unavailable')
    from seahub.utils import gen_file_get_url
    source = gen_file_get_url(token, os.path.basename(path))
    encoded = base64.b64encode(source.encode('utf-8')).decode('ascii')
    base = getattr(settings, 'CF_PREVIEW_PUBLIC_URL').strip().rstrip('/')
    return base + '/onlinePreview?' + urlencode({'url': encoded})



def lock_provider_ready(repo_id, path):
    """No public editing assembler is enabled until native publication is ready."""
    return False


def lock_status_map(repo_id, paths, username=''):
    """V2 path-keyed Guard status; no Resource, Device or Edit Session join."""
    from cloudfile_ext.v2.rust_edit import checkout_available
    if not checkout_available():
        return {}
    paths = tuple(dict.fromkeys(paths))
    if not paths:
        return {}
    if len(paths) > 200:
        raise ValueError('lock-status request budget exceeded')
    alias = getattr(settings, 'CF_DATABASE_ALIAS', 'cloudfile')
    hashes = [hashlib.sha256(path.encode('utf-8')).digest() for path in paths]
    placeholders = ', '.join(['%s'] * len(hashes))
    with connections[alias].cursor() as cursor:
        cursor.execute(
            'SELECT path,owner_native_user,lease_expires_at FROM cf_edit_guard '
            'WHERE repo_id=%s AND path_hash IN (' + placeholders + ') '
            'AND guard_id IS NOT NULL AND lease_expires_at>UTC_TIMESTAMP(6)',
            [repo_id] + hashes)
        rows = cursor.fetchall()
    return {
        path: {'is_locked': True, 'owner': owner,
               'kind': 'checkout', 'lease_until': expires,
               'locked_by_me': bool(username and owner == username)}
        for path, owner, expires in rows
    }



def get_actions(repo_id, path, can_edit=False, username=''):
    features = enabled_features()
    # CloudFile preview intentionally excludes Office handlers that rely on
    # ONLYOFFICE/Office Web App, even if Seafile advertises their file extension.
    # ONLYOFFICE remains an independently enabled editing action, not a viewer.
    native_preview_extensions = (frozenset(getattr(settings, 'CF_FILE_ACTION_PREVIEW_EXTENSIONS', ()))
                                 - OFFICE_DOCUMENT_EXTENSIONS)
    external_enabled = external_preview_enabled()
    preview_extensions = native_preview_extensions | (EXTERNAL_PREVIEW_EXTENSIONS if external_enabled else frozenset())
    ext = extension(path)
    preferred_preview = choose_preview_provider(
        ext, native_available=ext in native_preview_extensions,
        external_available=external_enabled and ext in EXTERNAL_PREVIEW_EXTENSIONS)
    actions = actions_for(
        path, features,
        preview_extensions,
        lock_provider_ready=lock_provider_ready(repo_id, path),
        can_edit=can_edit,
    )
    for action in actions:
        if action['id'] == 'native-preview' and action['available']:
            if preferred_preview == 'external':
                # The caller already passed path-level ACL checks. A configured
                # viewer URL alone does not prove that its converter is healthy.
                try:
                    preview_url = external_preview_url(repo_id, path, username)
                except Exception:
                    # Only fall back to native when its type is explicitly known;
                    # otherwise leave the preview unavailable, but keep download.
                    if ext in native_preview_extensions:
                        action['url'] = native_preview_url(repo_id, path)
                    else:
                        action['available'] = False
                        action['reason'] = 'preview_source_unavailable'
                else:
                    action['id'] = 'external-preview'
                    action['label'] = 'Preview with eap-fileview'
                    action['description'] = 'Read-only external document preview'
                    action['url'] = preview_url
                    if ext in native_preview_extensions:
                        # Client-visible alternative for conversion failure;
                        # this is not a claim that the viewer can auto-recover.
                        action['fallback_preview'] = {
                            'id': 'native-preview', 'url': native_preview_url(repo_id, path)}
            elif ext in native_preview_extensions:
                action['url'] = native_preview_url(repo_id, path)
    return actions


