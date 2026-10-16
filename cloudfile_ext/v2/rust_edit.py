"""Browser-authorized Rust edit handoff. No Device/Session/Intent database table.

This is a deliberately narrow scoped JWT minted ONLY from an authenticated
Seahub session. The Agent never receives the browser cookie or full API token.
Seafile/CF-ACL and the native repository version are checked before issuance;
Go Fileserver checks current permission again on every protected operation.
"""
import time
from urllib.parse import urlencode
from uuid import UUID, uuid4

import jwt
from django.conf import settings
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from seahub.api2.throttling import UserRateThrottle
from seahub.api2.utils import JWT_PRIVATE_KEY
from seaserv import seafile_api
from seahub.profile.models import Profile

from .acl_runtime import Authority


MAX_TICKET_SECONDS = 3600


def issue_ticket(*, username, uid, repo_id, path, mode, file_id, now, secret):
    """Stateless, path-scoped Agent permit. Never accept a caller-supplied actor."""
    if not isinstance(username, str) or not username or len(username) > 255:
        raise ValueError("invalid current user")
    if not isinstance(uid, str) or not uid or len(uid) > 225:
        raise ValueError("stable user UID required")
    UUID(repo_id)
    if mode not in ("optimistic-edit", "exclusive-edit"):
        raise ValueError("unsupported edit mode")
    if not isinstance(path, str) or not path.startswith("/") or path == "/" or (
            path.endswith("/") or "//" in path or "\\" in path or
            any(x in (".", "..") for x in path.split("/")) or
            len(path.encode("utf-8")) > 4096):
        raise ValueError("invalid edit path")
    if not isinstance(file_id, str) or len(file_id) != 40 or any(
            x not in "0123456789abcdef" for x in file_id):
        raise ValueError("invalid Seafile object")
    if not secret:
        raise ValueError("JWT secret not available")
    return jwt.encode({
        "iss": "cloudfile-v2-edit",
        "aud": "cloudfile-edit-agent",
        "sub": username, "uid": uid, "jti": str(uuid4()),
        "iat": now, "nbf": now, "exp": now + MAX_TICKET_SECONDS,
        "repo_id": repo_id, "path": path, "file_id": file_id,
        "mode": mode,
    }, secret, algorithm="HS256")


class RustLocalEditOpen(APIView):
    authentication_classes = (SessionAuthentication,)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    def post(self, request):
        if not getattr(settings, "CF_V2_AGENT_EDIT_ENABLED", False):
            return Response({"code": "EDIT_DISABLED"}, status=503)
        try:
            if set(request.data) != {"repo_id", "path", "mode"}:
                raise ValueError()
            repo_id = request.data["repo_id"]
            path = request.data["path"]
            mode = request.data["mode"]
            user = request.user.username
            uid = Profile.objects.get(user=user).login_id
            # V2 authority (including current SSO group mapping and deny) is
            # intentionally the sole browser-side policy resolver.
            decision = Authority(user).effective(repo_id, path, "file")
            if not decision.can_write:
                return Response({"code": "EDIT_DENIED"}, status=403)
            repo = seafile_api.get_repo(repo_id)
            if (repo is None or repo.is_virtual or repo.encrypted or
                    repo.version != 1):
                return Response({"code": "UNSUPPORTED_REPO"}, status=409)
            entry = seafile_api.get_dirent_by_path(repo_id, path)
            import stat
            if entry is None or not stat.S_ISREG(entry.mode):
                return Response({"code": "FILE_MISSING"}, status=404)
            file_id = entry.id
            now = int(time.time())
            token = issue_ticket(username=user, uid=uid, repo_id=repo_id, path=path,
                                 mode=mode, file_id=file_id, now=now,
                                 secret=JWT_PRIVATE_KEY)
            # Explicit origin, not forwarded claims from the caller body.
            instance = request.build_absolute_uri("/").rstrip("/")
            ticket_id = str(uuid4())
            uri = "cloudfile-open://v2/open?" + urlencode({
                "instance": instance, "session": ticket_id, "ticket": token
            })
            out = Response({"open_uri": uri, "mode": mode,
                            "file_id": file_id, "expires_at": now + MAX_TICKET_SECONDS})
            out["Cache-Control"] = "no-store"
            return out
        except (ValueError, TypeError, KeyError, AttributeError):
            return Response({"code": "BAD_EDIT_REQUEST"}, status=400)
        except PermissionError:
            return Response({"code": "EDIT_DENIED"}, status=403)
        except Exception:
            # Do not downgrade to raw repo/file token on missing policy.
            return Response({"code": "EDIT_UNAVAILABLE"}, status=503)
