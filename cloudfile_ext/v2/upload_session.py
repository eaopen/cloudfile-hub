# -*- coding: utf-8 -*-
"""Path-qualified upload session for ACL-managed libraries.

An ACL-managed library refuses unbound native tickets ("Path-qualified
authorization required" from `web-accesstoken-mgr.c`), so the browser cannot
use the legacy ``/api2/repos/{id}/upload-link/`` there. This endpoint
adjudicates the target directory with the same Authority the fileserver uses
and then mints the path-bound counterpart of the same ticket.

It is additive: libraries without stored rules keep using the legacy link,
whose tickets stay unbound and keep their native lifetime.
"""
import logging

from seahub.utils import gen_file_upload_url

from .acl_http import AuthenticatedACL, failure, response
from .acl_runtime import ACLUnavailable, Authority
from .native_gate import _canonical as canonical_dir

logger = logging.getLogger(__name__)


class UploadSession(AuthenticatedACL):
    def post(self, request, repo_id):
        try:
            parent_dir = canonical_dir(request.data.get('parent_dir') or '/')
            authority = Authority(request.user.username)
            decision = authority.effective(repo_id, parent_dir, 'dir')
            if not decision.can_write:
                raise PermissionError('write permission required')

            api = authority.api
            if parent_dir != '/' and not api.get_dir_id_by_path(repo_id, parent_dir):
                raise ValueError('missing target directory')

            mint = getattr(api, 'get_scoped_upload_token', None)
            if mint is None:
                # A Server without the path-bound upload ticket cannot serve an
                # ACL-managed library at all; say so instead of falling back to
                # the unbound link that the library refuses.
                raise ACLUnavailable('scoped upload ticket unavailable')
            token = mint(repo_id, parent_dir, request.user.username)
            if not token:
                raise ACLUnavailable('upload ticket refused')

            return response({
                'upload_url': gen_file_upload_url(token, 'upload-api'),
                'parent_dir': parent_dir,
            })
        except Exception as error:
            return failure(error)
