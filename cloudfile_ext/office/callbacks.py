# -*- coding: utf-8 -*-
"""OnlyOffice callback authentication and retry guard."""

import json

from django.conf import settings
from django.core.cache import cache
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt

from cloudfile_ext.office.idempotency import dedupe_key, signed_payload_matches


SUCCESS = HttpResponse('{"error": 0}', content_type='application/json')
FAILURE = HttpResponse('{"error": 1}', content_type='application/json')


def _callback_token(request, payload):
    token = payload.get('token', '')
    if token:
        return token
    header = getattr(settings, 'ONLYOFFICE_JWT_HEADER', 'Authorization')
    value = request.headers.get(header, '')
    return value[7:] if value.startswith('Bearer ') else value


def _authenticated(request, payload):
    """Require a Document Server JWT bound to the callback body."""
    secret = getattr(settings, 'ONLYOFFICE_JWT_SECRET', '')
    if not secret:
        return False
    token = _callback_token(request, payload)
    if not token:
        return False
    try:
        import jwt
        claims = jwt.decode(token, secret, algorithms=['HS256'],
                   options={'verify_aud': False})
    except Exception:
        return False
    return signed_payload_matches(claims, payload)


@csrf_exempt
def onlyoffice_callback(request):
    """Delegate one authenticated callback to CE, remembering successful saves.

    OnlyOffice retries status 2/6 callbacks.  The upstream CE callback writes a
    new Seafile version for each successful delivery, so a completed retry
    must short-circuit.  The completion mark is written *after* CE returns
    success; failed saves are deliberately retriable.
    """
    if request.method != 'POST':
        return FAILURE
    try:
        payload = json.loads(request.body)
    except (TypeError, ValueError):
        return FAILURE
    if not isinstance(payload, dict) or not _authenticated(request, payload):
        return FAILURE

    status = payload.get('status')
    key = dedupe_key(payload) if status in (2, 6) else None
    if key and cache.get(key):
        return SUCCESS

    from seahub.onlyoffice.views import onlyoffice_editor_callback
    response = onlyoffice_editor_callback(request)
    if key and response.status_code == 200 and b'"error": 0' in response.content:
        # Cache only confirmed completions. A transient Document Server or
        # fileserver failure must receive a retry rather than being suppressed.
        cache.set(key, True, 24 * 60 * 60)
    # A path/username pair is not proof of the checkout that belongs to this
    # editor session. Only the future durable publication receipt may release
    # its exact guard generation; never release an unrelated business checkout.
    return response
