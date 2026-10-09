"""Opt-in metadata on an already authorized native directory page."""
import logging
import posixpath

from rest_framework.response import Response
from seaserv import seafile_api

from cloudfile_ext.acl.service import directory_inputs
from cloudfile_ext.features import is_enabled
from cloudfile_ext.hooks import check_permission
from .contract import VERSION, MODEL
from .display import tags_for_page

logger = logging.getLogger(__name__)


def enrich_page(data, username, repo_id):
    # Native paging has path-aware permissions, including invisible filtering.
    # Apply the registered Hub hooks too before declaring acl_enforced to EAP.
    entries = []
    for entry in data['dirent_list']:
        path = posixpath.join(entry['parent_dir'], entry['name']).rstrip('/') or '/'
        permission = check_permission(username, repo_id, path, entry['permission'])
        if permission not in ('r', 'rw'):
            continue
        entries.append(dict(entry, permission=permission))
    data['dirent_list'] = entries
    data['acl_enforced'] = True
    if not is_enabled('CF_ENABLE_TAGS'):
        return
    targets = [(posixpath.join(e['parent_dir'], e['name']).rstrip('/') or '/', e['type'] == 'dir') for e in entries]
    try:
        repo = seafile_api.get_repo(repo_id)
        if repo is None:
            raise ValueError('Library unavailable')
        tags = tags_for_page(repo_id, repo, targets)
        results = [dict(path=p, is_dir=d, status='OK', tags=tags[(p, d)]) for p, d in targets]
    except Exception:
        # Display failure must not turn into "no tags" or break directory access.
        logger.exception('cloudfile: directory display tags unavailable')
        results = [dict(path=p, is_dir=d, status='FAILED', tags=None) for p, d in targets]
    data['tag_batch'] = dict(version=VERSION, model=MODEL, repo_id=repo_id, items=results)


def directory_response(view, instance, request, *args, **kwargs):
    # Scope the raw ACL cache reads to one response, removing per-item Redis I/O.
    # The opt-in only supports native pages; recursive/unlimited callers retain
    # their existing response and EAP's compatibility permission checks.
    with directory_inputs():
        response = view(instance, request, *args, **kwargs)
        if response.status_code == 200 and 'has_more' in response.data:
            try:
                repo_id = kwargs.get('repo_id') or args[0]
                enrich_page(response.data, request.user.username, repo_id)
            except Exception:
                logger.exception('cloudfile: directory permission enrichment failed')
                response = Response(dict(error='DIRECTORY_PERMISSION_UNAVAILABLE'), status=503)
        response['Cache-Control'] = 'no-store'
        return response
