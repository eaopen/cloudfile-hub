"""Bounded, user-authorized file/dir operation log for Etech.

Seafile CE Activity owns content/tree changes. The single CloudFile sidecar
owns tag and Checkout/Checkin transitions; Etech owns permission audit.
No history index, cursor table, Outbox, full-repo scan or Pro-only endpoint.
"""
import datetime
import hashlib
import json
from uuid import UUID

from django.db import connection
from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from seahub.api2.authentication import TokenAuthentication
from seahub.api2.throttling import UserRateThrottle

from .acl_policy import canonical_path
from .acl_runtime import Authority
from cloudfile_ext.audit.service import (
    AUDIT_EVENT_COLUMNS, serialize_activity, serialize_audit_event,
)
from cloudfile_ext.audit.models import AuditEvent

# Two small indexed reads, bounded even for a large library. A truncated
# result is explicit rather than silently claiming complete history.
SCAN_LIMIT = 500
MAX_RESULTS = 100


def _activity_rows(repo_id, cutoff):
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT id,op_type,obj_type,op_user,timestamp,repo_id,"
            "commit_id,path,detail FROM Activity "
            "WHERE repo_id=%s AND timestamp >= %s "
            "ORDER BY timestamp DESC,id DESC LIMIT %s",
            (repo_id, cutoff, SCAN_LIMIT),
        )
        return cursor.fetchall()


def _expand_activity(row):
    item = serialize_activity(row)
    detail = item.get('detail')
    if isinstance(detail, list):
        for entry in detail:
            if isinstance(entry, dict):
                clone = dict(item)
                clone['path'] = entry.get('path', item['path'])
                clone['old_path'] = entry.get('old_path', '')
                clone['detail'] = entry
                yield clone
    else:
        yield item


class OperationLogs(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    def get(self, request):
        """MVP self-path history; directory subtree browsing is not exposed
        until each child's current ACL can be checked without leaking names."""
        try:
            args = request.query_params
            if set(args) - {'repo_id', 'path', 'kind', 'days', 'limit'}:
                raise ValueError()
            repo_id = args['repo_id']
            if str(UUID(repo_id)) != repo_id:
                raise ValueError()
            path = canonical_path(args['path'])
            kind = args.get('kind', 'file')
            if kind not in ('file', 'dir') or (path == '/' and kind != 'dir'):
                raise ValueError()
            days = int(args.get('days', '90'))
            limit = int(args.get('limit', '50'))
            if not (1 <= days <= 365 and 1 <= limit <= MAX_RESULTS):
                raise ValueError()
        except (KeyError, TypeError, ValueError):
            return Response({'code':'BAD_OPERATION_LOG_REQUEST'}, status=400)
        try:
            if not Authority(request.user.username).effective(repo_id, path, kind).can_read:
                return Response({'code':'ACCESS_DENIED'}, status=403)
            cutoff = datetime.datetime.now(datetime.timezone.utc).replace(
                tzinfo=None) - datetime.timedelta(days=days)
            native = _activity_rows(repo_id, cutoff)
            path_hash = hashlib.sha256(path.encode('utf-8')).digest()
            extension = list(AuditEvent.objects.filter(
                repo_id=repo_id, path_hash=path_hash, occurred_at__gte=cutoff,
            ).order_by('-occurred_at', '-id').values_list(*AUDIT_EVENT_COLUMNS)[:SCAN_LIMIT])
            records = []
            expanded = 0
            scan_limited = len(native) == SCAN_LIMIT or len(extension) == SCAN_LIMIT
            for row in native:
                for event in _expand_activity(row):
                    expanded += 1
                    if expanded > 2000:
                        scan_limited = True
                        break
                    if event.get('path') == path or event.get('old_path') == path:
                        records.append(event)
                if expanded > 2000:
                    break
            for row in extension:
                event = serialize_audit_event(row)
                if event.get('path') == path or event.get('old_path') == path:
                    records.append(event)
            records.sort(key=lambda x: (str(x['time']), str(x['event_id'])), reverse=True)
            return Response({
                'events': records[:limit],
                'scan_limited': scan_limited,
                'returned': min(limit, len(records)),
                'scope': 'self',
            })
        except Exception:
            # No content, path or schema details are emitted on failure.
            return Response({'code':'OPERATION_LOG_UNAVAILABLE'},
                            status=status.HTTP_503_SERVICE_UNAVAILABLE)
