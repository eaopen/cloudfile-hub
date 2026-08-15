# -*- coding: utf-8 -*-
"""Read-only CloudFile operation-log endpoints, filters, export and page.

The file/directory event producer is Seafile's server -> seafevents
``repo-update`` stream, which diffs every committed tree (including WebDAV and
sync commits) and persists normalized records in its ``Activity`` table. That
authoritative table is one of two sources the reader merges; the other is
CloudFile's ``cf_audit_event`` sidecar, which holds tag changes that Activity
cannot represent and carries their before/after values (P2-08).
"""

import csv
import io

from django.db import connection
from django.db.models import Q
from django.core.exceptions import PermissionDenied
from django.http import Http404, HttpResponse
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
from cloudfile_ext.audit.service import (
    AUDIT_EVENT_COLUMNS, activity_where, merge_and_paginate, parse_filters,
)

MAX_EXPORT_ROWS = 50000

#: Column order for the CSV export, matching the unified event dict.
EXPORT_COLUMNS = (
    ('event_id', 'event_id'),
    ('time', 'time'),
    ('user', 'user'),
    ('operation', 'operation'),
    ('object_type', 'object_type'),
    ('object_id', 'object_id'),
    ('repo_id', 'repo_id'),
    ('source', 'source'),
    ('result', 'result'),
    ('path', 'path'),
    ('old_path', 'old_path'),
    ('before', 'before'),
    ('after', 'after'),
    ('failure_reason', 'failure_reason'),
    ('detail', 'detail'),
)


def _disabled():
    return api_error(status.HTTP_404_NOT_FOUND, 'Audit is disabled.')


def _activity_rows(spec):
    clauses, values = activity_where(spec)
    where = (' WHERE ' + ' AND '.join(clauses)) if clauses else ''
    with connection.cursor() as cursor:
        cursor.execute(
            'SELECT id, op_type, obj_type, op_user, timestamp, repo_id, '
            'commit_id, path, detail FROM Activity' + where, values)
        return cursor.fetchall()


def _audit_rows(spec):
    """Tag-change rows from cf_audit_event, filtered per spec."""
    from cloudfile_ext.audit.models import AuditEvent

    qs = AuditEvent.objects.all()
    if spec['repo_id']:
        qs = qs.filter(repo_id=spec['repo_id'])
    if spec['user']:
        qs = qs.filter(operator=spec['user'])
    if spec['op_type']:
        qs = qs.filter(operation=spec['op_type'])
    if spec['obj_type']:
        qs = qs.filter(object_type=spec['obj_type'])
    if spec['source']:
        qs = qs.filter(source=spec['source'])
    if spec['result']:
        qs = qs.filter(result=spec['result'])
    if spec['path']:
        qs = qs.filter(
            Q(source_path__icontains=spec['path']) |
            Q(target_path__icontains=spec['path']))
    if spec['start']:
        qs = qs.filter(occurred_at__gte=spec['start'])
    if spec['end']:
        qs = qs.filter(occurred_at__lte=spec['end'])
    return list(qs.values_list(*AUDIT_EVENT_COLUMNS))


def _query(spec):
    return merge_and_paginate(_activity_rows(spec), _audit_rows(spec), spec)


def _cell(value):
    """Flatten a list/dict value into a stable string for a CSV cell."""
    if value is None:
        return ''
    if isinstance(value, (dict, list)):
        import json
        return json.dumps(value, ensure_ascii=False)
    return str(value)


class AuditLogView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser,)
    throttle_classes = (UserRateThrottle,)

    def get(self, request):
        if not is_enabled('CF_ENABLE_AUDIT'):
            return _disabled()
        try:
            spec = parse_filters(request.GET)
        except ValueError as e:
            return api_error(status.HTTP_400_BAD_REQUEST, str(e))
        return Response(_query(spec))


class AuditExportView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser,)
    throttle_classes = (UserRateThrottle,)

    def get(self, request):
        if not is_enabled('CF_ENABLE_AUDIT'):
            return _disabled()
        try:
            spec = parse_filters(request.GET)
        except ValueError as e:
            return api_error(status.HTTP_400_BAD_REQUEST, str(e))

        # Cap the export to keep a single request bounded; operators can
        # narrow with filters to page through a larger history.
        spec['page'] = 1
        spec['per_page'] = MAX_EXPORT_ROWS
        result = _query(spec)

        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([label for label, _key in EXPORT_COLUMNS])
        for event in result['events']:
            writer.writerow([_cell(event.get(key)) for _label, key in EXPORT_COLUMNS])

        response = HttpResponse(buf.getvalue(), content_type='text/csv; charset=utf-8')
        response['Content-Disposition'] = 'attachment; filename="cloudfile-audit.csv"'
        # utf-8 BOM so spreadsheet applications open the CSV without mojibake.
        response.content = b'\xef\xbb\xbf' + response.content
        return response


def audit_page(request):
    """System-admin operation-log list; data stays behind the token API."""
    if not is_enabled('CF_ENABLE_AUDIT'):
        raise Http404
    if not request.user.is_staff:
        raise PermissionDenied
    return render(request, 'cloudfile_ext/audit.html')
