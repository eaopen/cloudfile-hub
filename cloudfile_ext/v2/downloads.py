"""V2 file authorization at native ticket issuance; consumption is native."""
import json
import posixpath

from django.http import HttpResponse
from rest_framework.response import Response
from seaserv import seafile_api
from seahub.utils import gen_file_get_url

from .acl_policy import PolicyError, canonical_path
from .acl_runtime import Authority


def file_download_response(request, repo_id, path, use_onetime):
    """Authorize the current actor on the exact file, then mint a native ticket.

    No per-transfer ACL query, new data table, revocation bus or separate
    file-byte proxy. Native reusable links expire without refreshing.
    """
    try:
        canonical_path(path)
        if path == '/':
            raise PolicyError('file path required')
        username = request.user.username
        if not Authority(username).effective(repo_id, path, 'file').can_read:
            raise PermissionError()
        grant = seafile_api.get_scoped_file_download_token(
            repo_id, path, username, use_onetime)
        if not grant:
            raise FileNotFoundError()
        response = HttpResponse(
            json.dumps(gen_file_get_url(grant['token'], posixpath.basename(path))),
            content_type='application/json')
        response['oid'] = grant['file_id']
        response['X-CloudFile-Download-TTL'] = str(grant['expires_in'])
        response['Cache-Control'] = 'no-store'
        return response
    except (PolicyError, ValueError, TypeError):
        return Response({'error_msg': 'Invalid file path.'}, status=400)
    except PermissionError:
        return Response({'error_msg': 'Permission denied.'}, status=403)
    except FileNotFoundError:
        return Response({'error_msg': 'File not found.'}, status=404)
    except Exception:
        # Never downgrade to the legacy object-only ticket on an ACL outage.
        return Response({'error_msg': 'File authorization unavailable.'}, status=503)
