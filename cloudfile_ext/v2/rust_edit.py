"""Browser-authorized Rust local view/edit handoff. No Device/Session/Intent table.

The local-view mode grants read only. Publish / checkout is forbidden by Go Fileserver.
This is a deliberately narrow scoped JWT minted ONLY from an authenticated
Seahub session. The Agent never receives the browser cookie or full API token.
Seafile/CF-ACL and the native repository version are checked before issuance;
Go Fileserver checks current permission again on every protected operation.
"""
import time
import hashlib
import os
import re
from urllib.parse import urlencode
from uuid import UUID, uuid4

import jwt
from django.conf import settings
from django.db import connection
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from seahub.api2.throttling import UserRateThrottle
from seahub.api2.utils import JWT_PRIVATE_KEY
from seaserv import seafile_api
from seahub.profile.models import Profile

from .acl_runtime import Authority


# 票据寿命按"一个弹性工作日"给：Guard 租约只有 10 分钟且滚动续租，票据却是硬过期，
# 1 小时会让长编辑在 Guard 仍有效时被 401 打断；18 小时会卡在"下午开工、干到凌晨、
# 次日继续"这种跨度的边缘。取 24 小时是为了跟墙钟对齐（"明天这一时刻"），并覆盖
# 两个日间加中间睡眠。服务端 cfEditClaimsFor 必须用同一个值，两处必须同批发布。
MAX_TICKET_SECONDS = 86400

# Existing Checkout configuration and schema are qualified together. Changing
# the capability or migrating Guard requires restarting Hub/native processes.
from functools import lru_cache


@lru_cache(maxsize=1)
def checkout_available():
    from cloudfile_ext.features import is_enabled
    # A baseline table is not feature activation. Keep ordinary transfer and
    # optimistic editing independent of Guard discovery when Checkout is off.
    if not is_enabled('CF_ENABLE_CHECKOUT'):
        return False
    from seahub.utils.db_api import SeafileDB
    schema = SeafileDB().db_name
    from .checkout_schema import path_checkout_available
    # Qualify the optional contract by columns/indexes, not by a colliding
    # table name. Native read/upload must not acquire a Checkout session.
    return path_checkout_available(connection, schema)


def checkout_for_repo(repo_id):
    """In-memory repository opt-in. OFF libraries never inspect Guard schema."""
    selected = getattr(settings, 'CF_CHECKOUT_REPOS', ())
    return (isinstance(selected, (tuple, list, set, frozenset)) and
            repo_id in selected and checkout_available())


def issue_ticket(*, username, uid, repo_id, path, mode, file_id, now, secret):
    """Stateless, path-scoped Agent permit. Never accept a caller-supplied actor."""
    if not isinstance(username, str) or not username or len(username) > 255:
        raise ValueError("invalid current user")
    if not isinstance(uid, str) or not uid or len(uid) > 225:
        raise ValueError("stable user UID required")
    UUID(repo_id)
    if mode not in ("local-view", "optimistic-edit", "exclusive-edit"):
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
        try:
            if set(request.data) != {"repo_id", "path", "mode"}:
                raise ValueError()
            repo_id = request.data["repo_id"]
            path = request.data["path"]
            mode = request.data["mode"]
            if mode not in ("local-view", "optimistic-edit", "exclusive-edit"):
                return Response({"code": "BAD_EDIT_REQUEST"}, status=400)
            if mode == "exclusive-edit" and not checkout_for_repo(repo_id):
                return Response({"code": "CHECKOUT_UNSUPPORTED"}, status=409)
            user = request.user.username
            uid = Profile.objects.get(user=user).login_id
            # V2 authority (including current SSO group mapping and deny) is
            # intentionally the sole browser-side policy resolver.
            decision = Authority(user).effective(repo_id, path, "file")
            # View-only must be usable by read-authorized users; never promote a
            # read grant into an optimistic or exclusive write capability.
            permitted = decision.can_read if mode == "local-view" else decision.can_write
            if not permitted:
                return Response({"code": "VIEW_DENIED" if mode == "local-view"
                                 else "EDIT_DENIED"}, status=403)
            repo = seafile_api.get_repo(repo_id)
            if (repo is None or repo.is_virtual or repo.encrypted or
                    repo.version != 1):
                return Response({"code": "UNSUPPORTED_REPO"}, status=409)
            entry = seafile_api.get_dirent_by_path(repo_id, path)
            import stat
            if entry is None or not stat.S_ISREG(entry.mode):
                return Response({"code": "FILE_MISSING"}, status=404)
            # CE14's `seafile_api.get_dirent_by_path` exposes `obj_id` / `obj_name`
            # only (every seahub caller uses those, see admin/library_dirents.py).
            # Reading `.id` raises AttributeError, which the handler below turns
            # into 400 BAD_EDIT_REQUEST -- surfacing as the eap 503
            # "CloudFile local open unavailable". Older bindings may still carry
            # `.id`, so keep the fallback.
            file_id = getattr(entry, "obj_id", None) or getattr(entry, "id", None)
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


class RustCheckoutInfo(APIView):
    """Current Checkout visibility, never a publication credential."""
    authentication_classes = (SessionAuthentication,)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    def get(self, request):
        try:
            args = request.query_params
            if set(args) != {"repo_id", "path"} or any(len(args.getlist(k)) != 1 for k in args):
                raise ValueError()
            repo_id, path = args["repo_id"], args["path"]
            UUID(repo_id)
            if not checkout_for_repo(repo_id):
                # OFF: no Guard SQL or schema discovery; ordinary edits remain available.
                return Response({"checkout_supported": False, "checked_out": False})
            if (not path.startswith("/") or path == "/" or "\\" in path or
                    "//" in path or len(path.encode("utf-8")) > 4096 or
                    any(x in (".", "..") for x in path.split("/"))):
                raise ValueError()
            viewer = request.user.username
            if not Authority(viewer).effective(repo_id, path, "file").can_read:
                return Response({"code": "EDIT_DENIED"}, status=403)
            # No table join to User/Device/Session: status comes from the one
            # native Guard row and its stable Checkout owner.
            db = os.environ.get("SEAFILE_MYSQL_DB_SEAFILE_DB_NAME", "")
            if not re.fullmatch(r"[A-Za-z0-9_]{1,64}", db):
                return Response({"code": "EDIT_UNAVAILABLE"}, status=503)
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT guard_id,owner_uid,owner_native_user,terminal_type,"
                    "terminal_name,checkout_ip,created_at,updated_at,lease_expires_at "
                    "FROM `" + db + "`.cf_edit_guard WHERE repo_id=%s AND path_hash=%s",
                    (repo_id, hashlib.sha256(path.encode("utf-8")).digest()),
                )
                rows = cursor.fetchall()
            if len(rows) > 1:
                return Response({"code": "EDIT_UNAVAILABLE"}, status=503)
            if not rows or rows[0][0] is None:
                return Response({"checkout_supported": True, "checked_out": False})
            guard, owner_uid, owner_user, terminal, name, ip, started, active, expires = rows[0]
            from django.utils import timezone
            if expires is None or expires <= timezone.now().replace(tzinfo=None):
                return Response({"checkout_supported": True, "checked_out": False})
            current_uid = Profile.objects.get(user=viewer).login_id
            owned_by_me = owner_uid == current_uid
            privileged = owned_by_me or bool(request.user.is_staff)
            details = {
                "checkout_supported": True,
                "checked_out": True,
                "owner_uid": owner_uid,
                "owner": owner_user,
                "checked_out_at": started.isoformat() + "Z",
                "last_activity_at": active.isoformat() + "Z",
                "expires_at": expires.isoformat() + "Z",
                # The dialog may offer resume only to the Guard owner; the Rust
                # Agent still verifies the original Guard proof before resuming.
                "checked_out_by_me": owned_by_me,
            }
            if privileged:
                details.update(terminal_type=terminal, terminal_name=name,
                               checkout_ip=ip)
            response = Response(details)
            response["Cache-Control"] = "no-store"
            return response
        except (ValueError, TypeError, KeyError):
            return Response({"code": "INVALID_REQUEST"}, status=400)
        except PermissionError:
            return Response({"code": "EDIT_DENIED"}, status=403)
        except Exception:
            return Response({"code": "EDIT_UNAVAILABLE"}, status=503)
