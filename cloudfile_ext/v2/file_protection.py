"""Permanent file protection for selected native repositories.

Independent from ACL and Checkout. A protected row identifies a canonical
repository path and its immutable native file version. Native fileservers
enforce it at Branch(master) publication; Hub handles management and display.
"""
import configparser
from functools import lru_cache
import hashlib
import os
import re
import stat
from pathlib import Path
from uuid import UUID

from django.db import connection, transaction
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from seahub.api2.authentication import TokenAuthentication, SessionAuthentication
from seaserv import seafile_api
from seahub.utils.db_api import SeafileDB

from .acl_policy import canonical_path
from .acl_runtime import Authority

MAX_BATCH = 200
MAX_DISPLAY = 1000
HEX40 = re.compile(r'[0-9a-f]{40}\Z')


class ProtectionUnavailable(Exception):
    pass


def _uuid(value):
    if not isinstance(value, str) or str(UUID(value)) != value:
        raise ValueError("canonical repository UUID required")
    return value


def _path(value):
    path = canonical_path(value)
    if path == '/' or path.endswith('/') or len(path.encode('utf-8')) > 4096:
        raise ValueError("regular file path required")
    return path


@lru_cache(maxsize=1)
def protected_repositories():
    """Use the same native seafile.conf for Hub/C/Go, with coordinated restart."""
    directory = os.environ.get('SEAFILE_CENTRAL_CONF_DIR') or os.environ.get('SEAFILE_DATA_DIR')
    if not directory:
        # Ordinary Seahub installations without the native scope remain OFF.
        # The native C/Go commit fence remains authoritative if misconfigured.
        return frozenset()
    parser = configparser.ConfigParser(interpolation=None)
    if not parser.read(str(Path(directory) / 'seafile.conf')):
        raise ProtectionUnavailable("seafile.conf unavailable")
    raw = parser.get('cloudfile', 'protection_repo_ids', fallback='')
    if len(raw) > 8192:
        raise ProtectionUnavailable("protection scope too large")
    if not raw.strip():
        return frozenset()
    try:
        values = [_uuid(value.strip()) for value in raw.split(',')]
    except (ValueError, TypeError):
        raise ProtectionUnavailable("invalid protection repository list") from None
    if len(values) != len(set(values)):
        raise ProtectionUnavailable("duplicate protected repository")
    return frozenset(values)


def selected(repo_id):
    _uuid(repo_id)
    return repo_id in protected_repositories()


def _tables():
    name = SeafileDB().db_name
    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_]{1,64}', name):
        raise ProtectionUnavailable("native schema unavailable")
    quote = chr(96)
    return tuple(f'{quote}{name}{quote}.{quote}{table}{quote}' for table in
                 ('cf_file_protection', 'cf_audit_event', 'Branch'))


def read_batch(repo_id, paths):
    """One indexed display query; OFF repositories never touch Protection SQL."""
    if len(paths) > MAX_DISPLAY or any(_path(p) != p for p in paths):
        raise ValueError("invalid protection batch")
    if not selected(repo_id):
        return {}
    hashes = {hashlib.sha256(p.encode('utf-8')).digest(): p for p in paths}
    if not hashes:
        return {}
    protection_table, _, _ = _tables()
    rows = []
    keys = list(hashes)
    with connection.cursor() as cursor:
        for start in range(0, len(keys), MAX_BATCH):
            window = keys[start:start + MAX_BATCH]
            placeholders = ','.join(['%s'] * len(window))
            cursor.execute(
                f'SELECT path_hash,path,file_id FROM {protection_table} '
                f'WHERE repo_id=%s AND path_hash IN ({placeholders})',
                [repo_id, *window])
            rows.extend(cursor.fetchall())
    result = {}
    for key, path, file_id in rows:
        key = bytes(key)
        if hashes.get(key) != path or key in result:
            raise ProtectionUnavailable("file protection state inconsistent")
        result[key] = file_id
    return {hashes[key]: value for key, value in result.items()}


def _reply(data, status=200):
    out = Response(data, status=status)
    out['Cache-Control'] = 'no-store'
    return out


def _admin(user):
    if not user.is_active or not user.is_staff:
        raise PermissionError("platform administrator required")
    permissions = getattr(user, 'admin_permissions', None)
    if permissions is None or not permissions.can_manage_library():
        raise PermissionError("library management permission required")


def _regular_file(repo_id, path):
    repo = seafile_api.get_repo(repo_id)
    if repo is None or repo.is_virtual or repo.encrypted or repo.version != 1:
        raise ValueError("unsupported native repository")
    entry = seafile_api.get_dirent_by_path(repo_id, path)
    if entry is None or not stat.S_ISREG(entry.mode):
        raise FileNotFoundError("file missing")
    file_id = getattr(entry, 'obj_id', None) or getattr(entry, 'id', None)
    head = getattr(repo, 'head_cmmt_id', None)
    if not HEX40.fullmatch(str(file_id)) or not HEX40.fullmatch(str(head)):
        raise ProtectionUnavailable("native file version unavailable")
    return file_id, head


def _state_change(user, body, protect):
    if not isinstance(body, dict) or set(body) != {'repo_id', 'path', 'expected_file_id'}:
        raise ValueError("explicit native file version required")
    repo_id, path = _uuid(body['repo_id']), _path(body['path'])
    expected = body['expected_file_id']
    if not isinstance(expected, str) or not HEX40.fullmatch(expected):
        raise ValueError("expected_file_id invalid")
    _admin(user)
    if not selected(repo_id):
        return _reply({'code': 'PROTECTION_NOT_ENABLED'}, 409)
    if not Authority(user.username).effective(repo_id, path, 'file').can_read:
        raise PermissionError("native file read denied")
    file_id, original_head = _regular_file(repo_id, path)
    if file_id != expected:
        return _reply({'code': 'FILE_VERSION_CHANGED'}, 409)
    table, audit_table, branch_table = _tables()
    digest = hashlib.sha256(path.encode('utf-8')).digest()
    with transaction.atomic():
        with connection.cursor() as cursor:
            cursor.execute(
                f"SELECT commit_id FROM {branch_table} WHERE repo_id=%s AND name='master' FOR UPDATE",
                [repo_id])
            row = cursor.fetchone()
            if row is None or row[0] != original_head:
                return _reply({'code': 'FILE_VERSION_CHANGED'}, 409)
            cursor.execute(
                f'SELECT file_id,path FROM {table} WHERE repo_id=%s AND path_hash=%s FOR UPDATE',
                [repo_id, digest])
            current = cursor.fetchone()
            if current and current[1] != path:
                raise ProtectionUnavailable("protection hash collision")
            if protect:
                if current and current[0] != file_id:
                    return _reply({'code': 'PROTECTION_CONFLICT'}, 409)
                if current is None:
                    cursor.execute(
                        f'INSERT INTO {table}(repo_id,path_hash,path,file_id,protected_by,protected_at) '
                        f'VALUES (%s,%s,%s,%s,%s,UTC_TIMESTAMP(6))',
                        [repo_id, digest, path, file_id, user.username])
            else:
                if current is None:
                    return _reply({'protected': False, 'file_id': file_id})
                cursor.execute(f'DELETE FROM {table} WHERE repo_id=%s AND path_hash=%s',
                               [repo_id, digest])
            if (protect and current is None) or (not protect and current is not None):
                cursor.execute(
                    f'INSERT INTO {audit_table}(repo_id,object_type,object_id,operation,operator,source,'
                    f'source_path,path_hash,commit_id,result,occurred_at) '
                    f"VALUES (%s,'file',%s,%s,%s,'web',%s,%s,%s,'success',UTC_TIMESTAMP(6))",
                    [repo_id, file_id, 'file_protect' if protect else 'file_unprotect',
                     user.username, path if len(path) <= 1000 else None, digest, original_head])
    return _reply({'protected': protect, 'file_id': file_id})


def _failure(err):
    if isinstance(err, (ValueError, TypeError, KeyError)):
        return _reply({'code': 'BAD_PROTECTION_REQUEST'}, 400)
    if isinstance(err, PermissionError):
        return _reply({'code': 'PROTECTION_DENIED'}, 403)
    if isinstance(err, FileNotFoundError):
        return _reply({'code': 'FILE_MISSING'}, 404)
    return _reply({'code': 'PROTECTION_UNAVAILABLE'}, 503)


class FileProtectionStatus(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        try:
            if set(request.query_params) != {'repo_id', 'path'}:
                raise ValueError()
            repo_id = _uuid(request.query_params['repo_id'])
            path = _path(request.query_params['path'])
            if not Authority(request.user.username).effective(repo_id, path, 'file').can_read:
                raise PermissionError()
            file_id, _ = _regular_file(repo_id, path)
            data = read_batch(repo_id, [path])
            return _reply({'protected': path in data, 'file_id': file_id,
                           'protection_supported': selected(repo_id)})
        except Exception as err:
            return _failure(err)

    def post(self, request):
        try:
            if not isinstance(request.data, dict) or set(request.data) != {'repo_id', 'paths'}:
                raise ValueError()
            repo_id = _uuid(request.data['repo_id'])
            paths = request.data['paths']
            if not isinstance(paths, list) or not 1 <= len(paths) <= MAX_BATCH:
                raise ValueError()
            normalized = [_path(p) for p in paths]
            authority = Authority(request.user.username)
            for path in normalized:
                if not authority.effective(repo_id, path, 'file').can_read:
                    raise PermissionError()
                _regular_file(repo_id, path)
            protected = read_batch(repo_id, normalized)
            return _reply({'protection_supported': selected(repo_id), 'items': [
                {'path': path, 'protected': path in protected} for path in normalized]})
        except Exception as err:
            return _failure(err)


class FileProtect(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            return _state_change(request.user, request.data, True)
        except Exception as err:
            return _failure(err)


class FileUnprotect(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            return _state_change(request.user, request.data, False)
        except Exception as err:
            return _failure(err)
