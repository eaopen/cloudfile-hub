# -*- coding: utf-8 -*-
"""Read-only CloudFile operation-log endpoints and page.

The event producer is Seafile's server -> seafevents ``repo-update`` stream.
seafevents diffs every committed tree (including WebDAV and sync commits) and
persists the normalized file and directory records in its ``Activity`` table.
Reading that authoritative table avoids a second, partial Hub-only audit trail.
"""

import json

from django.db import connection
from django.core.exceptions import PermissionDenied
from django.http import Http404
from django.shortcuts import render
from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView

from seahub.api2.authentication import TokenAuthentication
from seahub.api2.throttling import UserRateThrottle
from seahub.api2.utils import api_error

from cloudfile_ext.features import is_enabled
from cloudfile_ext.audit.service import filters

MAX_PAGE_SIZE = 200


def _disabled():
    return api_error(status.HTTP_404_NOT_FOUND, 'Audit is disabled.')


def _list(params):
    try:
        page = max(1, int(params.get('page', '1')))
        per_page = min(MAX_PAGE_SIZE, max(1, int(params.get('per_page', '50'))))
    except ValueError:
        raise ValueError('page or per_page invalid.')
    clauses, values = filters(params)
    where = (' WHERE ' + ' AND '.join(clauses)) if clauses else ''
    with connection.cursor() as cursor:
        cursor.execute('SELECT COUNT(*) FROM Activity' + where, values)
        total = cursor.fetchone()[0]
        cursor.execute(
            'SELECT id, op_type, obj_type, op_user, timestamp, repo_id, '
            'commit_id, path, detail FROM Activity' + where +
            ' ORDER BY timestamp DESC, id DESC LIMIT %s OFFSET %s',
            values + [per_page, (page - 1) * per_page])
        rows = cursor.fetchall()
    events = []
    for row in rows:
        detail = json.loads(row[8] or '{}')
        events.append({
            'id': row[0], 'operation': row[1], 'object_type': row[2],
            'user': row[3], 'time': row[4], 'repo_id': row[5],
            'commit_id': row[6], 'path': row[7],
            'old_path': detail.get('old_path', ''), 'detail': detail,
        })
    return {'events': events, 'total': total, 'page': page, 'per_page': per_page}


class AuditLogView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser,)
    throttle_classes = (UserRateThrottle,)

    def get(self, request):
        if not is_enabled('CF_ENABLE_AUDIT'):
            return _disabled()
        try:
            return Response(_list(request.GET))
        except ValueError as e:
            return api_error(status.HTTP_400_BAD_REQUEST, str(e))


def audit_page(request):
    """System-admin operation-log list; data stays behind the token API."""
    if not is_enabled('CF_ENABLE_AUDIT'):
        raise Http404
    if not request.user.is_staff:
        raise PermissionDenied
    return render(request, 'cloudfile_ext/audit.html')
