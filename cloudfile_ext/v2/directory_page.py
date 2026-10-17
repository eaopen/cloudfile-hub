"""Paged CE directory listing (`start`/`limit`) served by the V2 authority.

Restores the v0.9 page protocol that EAP items-page already consumes, without
a native extension: one bounded native window, every child decided by the same
Authority as the CloudFile ACL APIs. Requests without start/limit never reach
this module and keep the CE14 response unchanged.
"""
import logging
import re

from rest_framework import status
from rest_framework.response import Response

from seahub.api2.utils import api_error
from seahub.utils import normalize_dir_path
from seahub.utils.timeutils import timestamp_to_isoformat_timestr

from .acl_runtime import PAGE_LIMIT_MAX, Authority, DirectoryChanged

logger = logging.getLogger(__name__)

PAGE_DEFAULT = 200
OBJECT_ID = re.compile(r'[0-9a-f]{40}')



def _arguments(request):
    args = request.GET
    # Recursive, ancestor and thumbnail variants are not part of the page contract.
    if (args.get('recursive', '0') != '0' or args.get('with_parents', 'false') != 'false' or
            args.get('with_thumbnail', 'false') != 'false' or args.get('t', '')):
        raise ValueError()
    start = int(args.get('start') or '0')
    limit = int(args.get('limit') or str(PAGE_DEFAULT))
    if not 1 <= limit <= PAGE_LIMIT_MAX:
        raise ValueError()
    if_dir_id = args.get('if_dir_id') or None
    if if_dir_id is not None and not OBJECT_ID.fullmatch(if_dir_id):
        raise ValueError()
    return normalize_dir_path(args.get('p', '/')), start, limit, if_dir_id


def _dirent(entry, parent_dir, kind, permission):
    item = dict(type=kind, id=entry.obj_id, name=entry.obj_name,
                mtime=timestamp_to_isoformat_timestr(entry.mtime),
                permission=permission, parent_dir=parent_dir)
    if kind == 'file':
        item['size'] = entry.size
    return item


def directory_page(request, repo_id):
    try:
        parent_dir, start, limit, if_dir_id = _arguments(request)
    except ValueError:
        return api_error(status.HTTP_400_BAD_REQUEST, 'start/limit invalid.')
    from seaserv import seafile_api
    if not seafile_api.get_repo(repo_id):
        return api_error(status.HTTP_404_NOT_FOUND, 'Library %s not found.' % repo_id)
    try:
        # Not CE check_folder_permission: a directory-only ACL grant must page
        # its folder without whole-library native permission.
        page = Authority(request.user.username).page(repo_id, parent_dir.rstrip('/') or '/',
                                                     start=start, limit=limit, if_dir_id=if_dir_id)
    except DirectoryChanged:
        return api_error(status.HTTP_409_CONFLICT, 'Folder changed; restart paging.')
    except ValueError:
        return api_error(status.HTTP_400_BAD_REQUEST, 'start/limit invalid.')
    except PermissionError:
        return api_error(status.HTTP_403_FORBIDDEN, 'Permission denied.')
    except FileNotFoundError:
        return api_error(status.HTTP_404_NOT_FOUND, 'Folder %s not found.' % parent_dir)
    except Exception:
        # ACL, identity or native RPC failure must never fall back to an
        # unfiltered or silently truncated listing.
        logger.exception('CloudFile directory page unavailable')
        return api_error(status.HTTP_503_SERVICE_UNAVAILABLE, 'Directory pagination unavailable.')
    response = Response(dict(
        user_perm=page['parent'].permission,
        dir_id=page['dir_id'],
        dirent_list=[_dirent(entry, parent_dir, kind, permission)
                     for entry, _, kind, permission in page['items']],
        has_more=page['next_start'] is not None,
        next_start=page['next_start'],
        scanned_count=page['scanned_count'],
        scan_exhausted=page['next_start'] is None,
        acl_enforced=True,
    ))
    response['Cache-Control'] = 'no-store'
    return response
