# -*- coding: utf-8 -*-
"""URL-shadow views for copy/move (P2-06).

Both classes shadow the native ``/api2/repos/{repo}/fileops/{copy,move}/``
endpoints (cloudfile_ext.urls is prepended to Seahub's patterns -- see
seahub/utils/rooturl.py), so no upstream file is edited.

The shadow only takes over the JSON contract the review matrix drives
(``operation`` + ``src_repo_id``/``dst_repo_id``/``dirent_type``); any request
that is not that contract -- the native form shape the older UI still uses --
is delegated straight back to upstream's view, byte for byte. When
``CF_ENABLE_FILEOPS`` is off, ``register()`` adds no routes and the native view
handles everything, which is the "switch off = native CE" rule.
"""

from rest_framework import status
from rest_framework.response import Response

from seahub.api2.utils import api_error
from seahub.api2.views import (
    OpCopyView as NativeOpCopyView, OpMoveView as NativeOpMoveView,
)

from cloudfile_ext.fileops import service


def _handle(request, operation, repo_id):
    payload = dict(request.data)
    payload['operation'] = operation
    payload.setdefault('src_repo_id', repo_id)
    username = request.user.username

    # Idempotency first: a repeated click must resolve to the first task, not
    # re-run the precheck (a completed move has already removed its source).
    key = service.idempotency_key(username, operation, payload)
    cached = service.lookup_cached(username, key)
    if cached is not None:
        return Response(cached)

    try:
        evaluation = service.evaluate(request, operation, payload)
    except service.PrecheckError as exc:
        return api_error(exc.http_status, str(exc))

    # Preview mode (move permission-impact confirm): return the precheck
    # outcome — affected members and per-item failures — without performing
    # the move. The frontend uses this to warn before a move that would
    # strip access from existing members.
    if payload.get('preview'):
        return Response({
            'done': not evaluation['to_run'],
            'failures': evaluation['failures'],
            'affected_members': evaluation['affected_members'],
            'item_count': len(evaluation['to_run']),
        })

    if not evaluation['to_run']:
        # Every item failed precheck: report the failure list, no task.
        return Response(service.failures_only(evaluation))

    try:
        result = service.submit(request, operation, evaluation)
    except Exception:
        # submit() already logged the cause; do not leak it to the client.
        return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR,
                         'Internal Server Error')
    return Response(result)


class FileopsCopyView(NativeOpCopyView):

    def post(self, request, repo_id, format=None):
        if not request.data.get('operation'):
            return super().post(request, repo_id, format=format)
        return _handle(request, service.OPERATION_COPY, repo_id)


class FileopsMoveView(NativeOpMoveView):

    def post(self, request, repo_id, format=None):
        if not request.data.get('operation'):
            return super().post(request, repo_id, format=format)
        return _handle(request, service.OPERATION_MOVE, repo_id)
