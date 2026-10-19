"""Path-authorized native file tickets; grants expire without per-read ACL calls."""
import json
import posixpath

from django.http import HttpResponse
from rest_framework.response import Response
from seaserv import seafile_api

from seahub.utils import gen_file_get_url
from .acl_policy import canonical_path, PolicyError
from .acl_runtime import Authority


def file_download_response(request, repo_id, path, use_onetime):
    """Use the same V2 authority as directory listings, never a staff token.

    Native RPC is private and resolves the file object itself. Once issued, the
    read-only grant may be reused until expiry, including after a permission
    change: this is the agreed internal-document performance tradeoff.
    """
    try:
        canonical_path(path)
        if path == '/':
            raise PolicyError('file path required')
        username = request.user.username
        if not Authority(username).effective(repo_id, path, 'file').can_read:
            raise PermissionError()
        grant = seafile_api.get_scoped_download_token(
            repo_id, path, username, use_onetime)
        if not grant:
            raise FileNotFoundError()
        response = HttpResponse(
            json.dumps(gen_file_get_url(grant['token'], posixpath.basename(path))),
            content_type='application/json')
        response['oid'] = grant['file_id']
        # EAP must not keep its redirect ticket longer than this native grant.
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
        # No fallback to object-only tickets if policy/native support is down.
        return Response({'error_msg': 'File authorization unavailable.'}, status=503)
