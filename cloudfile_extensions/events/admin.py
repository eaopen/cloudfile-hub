"""Bounded system-administrator views of CloudFile and Seahub audit facts."""

import base64
import binascii
from datetime import timezone
import hashlib
import hmac
import json
import re
from uuid import UUID

from django.conf import settings
from django.db.models import Q
from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView

from seahub.api2.authentication import TokenAuthentication
from seahub.api2.throttling import UserRateThrottle
from seahub.sysadmin_extra.models import UserLoginLog

from ..common.validation import utc_time
from ..common.errors import ContractError
from .query import AuditReader


CATEGORIES = {"login", "access", "updates", "permissions"}
OPERATIONS = {
    "access": ("operation IN ('file.view','file.download')", ()),
    "updates": ("(operation LIKE %s OR operation LIKE %s) AND operation NOT IN ('file.view','file.download')",
                ("file.%", "dir.%")),
    "permissions": ("(operation LIKE %s OR operation LIKE %s OR operation LIKE %s OR "
                    "operation LIKE %s OR operation LIKE %s OR operation LIKE %s)",
                    ("acl.%", "admin.%", "permission.%", "share.%", "library.admin.%", "library.share.%")),
}


def _invalid():
    return Response({"error": "Invalid audit query or cursor."}, status=status.HTTP_400_BAD_REQUEST)


def _secret():
    secret = getattr(settings, "CLOUDFILE_AUDIT_CURSOR_SECRET", None)
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise ValueError("audit cursor secret is unavailable")
    return secret


def _encode_cursor(scope, position):
    raw = json.dumps({"scope": scope, "position": position}, sort_keys=True, separators=(",", ":")).encode()
    signature = hmac.new(_secret(), b"cf.admin.audit.v1\n" + raw, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(raw + signature).decode().rstrip("=")


def _decode_cursor(cursor, scope):
    if cursor is None:
        return None
    if not isinstance(cursor, str) or len(cursor) > 4096 or not re.fullmatch(r"[A-Za-z0-9_-]+", cursor):
        raise ValueError("invalid cursor")
    signed = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
    raw, signature = signed[:-32], signed[-32:]
    if len(signature) != 32 or not hmac.compare_digest(signature,
            hmac.new(_secret(), b"cf.admin.audit.v1\n" + raw, hashlib.sha256).digest()):
        raise ValueError("invalid cursor")
    document = json.loads(raw)
    if set(document) != {"scope", "position"} or document["scope"] != scope:
        raise ValueError("invalid cursor scope")
    position = document["position"]
    if (not isinstance(position, list) or len(position) != 2 or type(position[1]) is not int
            or position[1] < 1):
        raise ValueError("invalid cursor position")
    stamp = utc_time(position[0])
    return stamp, position[1]


def _query_options(request, category):
    allowed = {"start", "end", "limit", "cursor", "repo_id", "actor"}
    if category not in CATEGORIES or set(request.GET) - allowed or any(
            len(request.GET.getlist(key)) != 1 for key in request.GET):
        raise ValueError("invalid query")
    if len(request.META.get("QUERY_STRING", "").encode("utf-8")) > 8192:
        raise ValueError("query too large")
    start, end = utc_time(request.GET["start"]), utc_time(request.GET["end"])
    if not 0 < (end - start).total_seconds() <= 31 * 86400:
        raise ValueError("invalid time window")
    raw_limit = request.GET.get("limit", "100")
    if not re.fullmatch(r"[1-9][0-9]{0,2}", raw_limit) or int(raw_limit) > 200:
        raise ValueError("invalid page size")
    repo = request.GET.get("repo_id")
    if category == "login" and repo is not None:
        raise ValueError("login has no library")
    if repo is not None:
        repo = str(UUID(repo))
    actor = request.GET.get("actor")
    if actor is not None and (not actor or len(actor) > 255 or "\x00" in actor):
        raise ValueError("invalid actor")
    scope = {"category": category,
             "start": start.isoformat().replace("+00:00", "Z"),
             "end": end.isoformat().replace("+00:00", "Z"),
             "repo_id": repo, "actor": actor}
    position = _decode_cursor(request.GET.get("cursor"), scope)
    if position is not None and not start <= position[0] < end:
        raise ValueError("cursor outside time window")
    return scope, int(raw_limit), position


def _login_page(scope, limit, position):
    # Seahub stores naive UTC datetimes (USE_TZ=False). Keep ORM bounds naive
    # and mark returned values as UTC without converting through host local time.
    start, end = utc_time(scope["start"]).replace(tzinfo=None), utc_time(scope["end"]).replace(tzinfo=None)
    logs = UserLoginLog.objects.filter(login_date__gte=start, login_date__lt=end)
    if scope["actor"]:
        logs = logs.filter(username=scope["actor"])
    if position:
        stamp = position[0].replace(tzinfo=None)
        logs = logs.filter(Q(login_date__lt=stamp) |
                           Q(login_date=stamp, id__lt=position[1]))
    rows = list(logs.order_by("-login_date", "-id").values(
        "id", "username", "login_date", "login_ip", "login_success")[:limit + 1])
    items = [{"id": str(row["id"]), "occurred_at": row["login_date"].replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z"),
              "actor": row["username"], "ip": row["login_ip"],
              "result": "succeeded" if row["login_success"] else "failed"} for row in rows[:limit]]
    next_cursor = None
    if len(rows) > limit:
        last = rows[limit - 1]
        next_cursor = _encode_cursor(scope, [last["login_date"].replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z"), last["id"]])
    return {"items": items, "next_cursor": next_cursor}


def _event_page(scope, limit, position):
    import MySQLdb
    config = settings.CLOUDFILE_POLICY_CONFIG["database"]
    connection = MySQLdb.connect(host=config["host"], port=config.get("port", 3306),
        user=config["user"], password=config["password"], database=config["name"],
        charset="utf8mb4", autocommit=True, connect_timeout=5, read_timeout=10)
    try:
        with connection.cursor() as sql:
            sql.execute("SELECT ENGINE FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='cf_audit_event'")
            if sql.fetchall() != (("InnoDB",),):
                raise ValueError("audit storage unavailable")
            sql.execute("SELECT column_name,non_unique,sub_part FROM information_schema.statistics "
                        "WHERE table_schema=DATABASE() AND table_name='cf_audit_event' "
                        "AND index_name='audit_admin_page' ORDER BY seq_in_index")
            if sql.fetchall() != (("occurred_at", 1, None), ("id", 1, None)):
                raise ValueError("audit index unavailable")
            clause, category_values = OPERATIONS[scope["category"]]
            clauses = ["occurred_at>=%s", "occurred_at<%s", clause]
            values = [utc_time(scope["start"]).replace(tzinfo=None),
                      utc_time(scope["end"]).replace(tzinfo=None), *category_values]
            if scope["repo_id"] is not None:
                clauses.append("repo_id=%s")
                values.append(scope["repo_id"])
            if scope["actor"] is not None:
                clauses.append("(actor_user_id=%s OR (actor_user_id IS NULL AND operator=%s))")
                values.extend([scope["actor"], scope["actor"]])
            if position:
                clauses.append("(occurred_at<%s OR (occurred_at=%s AND id<%s))")
                values.extend([position[0].replace(tzinfo=None), position[0].replace(tzinfo=None), position[1]])
            fields = AuditReader.FIELDS
            sql.execute("SELECT " + ",".join(fields) + " FROM cf_audit_event FORCE INDEX (audit_admin_page) WHERE " +
                        " AND ".join(clauses) + " ORDER BY occurred_at DESC,id DESC LIMIT %s", (*values, limit + 1))
            rows = sql.fetchall()
    finally:
        connection.close()
    items = []
    for row in rows[:limit]:
        event = dict(zip(fields, row))
        event["id"] = str(event["id"])
        for name in ("occurred_at", "recorded_at"):
            if event[name] is not None:
                event[name] = event[name].replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
        items.append(event)
    next_cursor = None
    if len(rows) > limit:
        last = rows[limit - 1]
        next_cursor = _encode_cursor(scope, [last[3].replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z"), last[0]])
    return {"items": items, "next_cursor": next_cursor}


class CloudFileAdminAuditView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser,)
    throttle_classes = (UserRateThrottle,)
    http_method_names = ("get",)

    def get(self, request, category):
        if not getattr(settings, "CLOUDFILE_AUDIT_QUERY_ENABLED", False):
            return Response(status=status.HTTP_404_NOT_FOUND)
        if not request.user.admin_permissions.can_view_user_log():
            return Response({"error": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        try:
            scope, limit, position = _query_options(request, category)
        except (KeyError, ValueError, TypeError, UnicodeError, binascii.Error, ContractError):
            return _invalid()
        try:
            result = _login_page(scope, limit, position) if category == "login" else _event_page(scope, limit, position)
        except Exception:
            return Response({"error": "Audit storage is unavailable."}, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        response = Response(result)
        response["Cache-Control"] = "no-store, max-age=0"
        response["Vary"] = "Cookie, Authorization"
        return response
