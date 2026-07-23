# -*- coding: utf-8 -*-
"""Endpoints for the directory sync: look at it, run it, receive a push.

Everything here is administrative or machine-to-machine. There is deliberately
no end-user surface: group membership is the directory's to decide, and an
endpoint that let a user edit it would make the next sync tick undo their
change -- worse than not offering it.
"""

import logging
import time

from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import AllowAny, IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView

from seahub.api2.authentication import TokenAuthentication
from seahub.api2.throttling import AnonRateThrottle, UserRateThrottle
from seahub.api2.utils import api_error

from cloudfile_ext.features import is_enabled
from cloudfile_ext.sso import directory, reconcile, service
from cloudfile_ext.sso.models import SSOGroupMap, SSOSyncState

logger = logging.getLogger(__name__)


def _feature_off():
    return api_error(status.HTTP_404_NOT_FOUND, 'Feature is not enabled.')


class AdminSSOSyncView(APIView):
    """Report the state of directory mapping, or run a sync now.

    GET answers the question an operator actually has, which is not "is the
    code installed" but "is what I am looking at current?" -- so it reports the
    last run, its outcome, and on request the plan the next run would apply.
    """

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser,)
    throttle_classes = (UserRateThrottle,)

    def get(self, request):
        if not is_enabled('CF_ENABLE_SSO'):
            return _feature_off()

        from cloudfile_ext.registry import registry

        state = SSOSyncState.objects.get_state(service.SYNC_TASK)
        source = directory.active(registry)

        body = {
            'provider': service.PROVIDER,
            'directory': directory.selected_name(),
            'mapped_groups': SSOGroupMap.objects.filter(
                provider=service.PROVIDER).count(),
            'last_run': state.last_run if state else None,
            'last_status': state.status if state else None,
            'last_detail': state.detail if state else None,
        }

        # The dry run is opt-in because it calls the directory service, and a
        # status page that reaches out to a third party every time somebody
        # loads it is a status page that goes down with them.
        if request.GET.get('dry_run', '').lower() == 'true':
            if source is None:
                body['plan'] = None
                body['plan_error'] = 'no CF_PROVIDER_SSO_DIRECTORY selected'
            else:
                try:
                    plan, notes = service.build_plan(source)
                    body['plan'] = plan.counts()
                    body['plan_notes'] = notes
                except (reconcile.SyncRefused, directory.DirectoryError,
                        service.SyncNotConfigured) as exc:
                    body['plan'] = None
                    body['plan_error'] = str(exc)

        return Response(body)

    def post(self, request):
        if not is_enabled('CF_ENABLE_SSO'):
            return _feature_off()

        result = service.sync()
        # A refused or errored sync is reported as 200 with a status field
        # rather than as an HTTP error: the request itself was handled
        # correctly, and the outcome is the payload. Callers that care check
        # `status`, which is also what cf-worker records.
        return Response(result)


class AdminSSOGroupMapView(APIView):
    """List the groups CloudFile manages, or stop managing one.

    DELETE removes the mapping only. The group survives, keeps its members and
    its libraries, and simply stops being synced -- see
    cloudfile_ext.sso.reconcile for why deleting is never a sync's decision to
    make, and by extension not this endpoint's either.
    """

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser,)
    throttle_classes = (UserRateThrottle,)

    def get(self, request):
        if not is_enabled('CF_ENABLE_SSO'):
            return _feature_off()

        rows = SSOGroupMap.objects.filter(
            provider=service.PROVIDER).order_by('external_id')
        return Response({
            'mappings': [
                {
                    'external_id': row.external_id,
                    'group_id': row.group_id,
                    'name': row.name,
                    'ctime': row.ctime,
                    'mtime': row.mtime,
                }
                for row in rows
            ],
        })

    def delete(self, request):
        if not is_enabled('CF_ENABLE_SSO'):
            return _feature_off()

        external_id = request.GET.get('external_id', '').strip()
        if not external_id:
            return api_error(status.HTTP_400_BAD_REQUEST,
                             'external_id invalid.')

        deleted, _ = SSOGroupMap.objects.unmap(service.PROVIDER, external_id)
        if not deleted:
            return api_error(status.HTTP_404_NOT_FOUND, 'Mapping not found.')
        return Response({'success': True})


class SSODirectoryWebhookView(APIView):
    """Let the directory say "something changed" instead of waiting for a tick.

    This is what turns the eventual consistency of pulling from minutes into
    seconds, and it is why pulling is an acceptable design at all.

    The body is ignored on purpose. Accepting a payload that says *what*
    changed would mean trusting an unauthenticated-by-session caller to tell us
    which groups to modify; instead the call means only "re-read the directory
    now", and everything applied still comes from the directory itself over the
    connection we opened.
    """

    authentication_classes = ()
    permission_classes = (AllowAny,)
    throttle_classes = (AnonRateThrottle,)

    def post(self, request):
        if not is_enabled('CF_ENABLE_SSO'):
            return _feature_off()

        secret = _webhook_secret()
        if not secret:
            # No secret means no way to tell the directory apart from anyone
            # else on the network, and this endpoint triggers outbound calls.
            # Refusing to exist is the only safe unconfigured state.
            return _feature_off()

        if not _verify(request, secret):
            return api_error(status.HTTP_403_FORBIDDEN, 'Invalid signature.')

        result = service.sync()
        return Response(result)


def _webhook_secret():
    from django.conf import settings
    return getattr(settings, 'CF_SERVICE_SSO_DIRECTORY_SECRET', '')


def _verify(request, secret):
    """Check the same HS256 token cloudfile_ext.external_service sends.

    Symmetry is the point: an operator who configured the outbound direction
    has already got everything the inbound one needs, and there is one signing
    scheme in CloudFile rather than two.
    """
    header = request.META.get('HTTP_AUTHORIZATION', '')
    if not header.startswith('Token '):
        return False

    try:
        import jwt
    except ImportError:                                     # pragma: no cover
        logger.error('PyJWT missing; cannot verify the SSO webhook')
        return False

    try:
        payload = jwt.decode(header[len('Token '):], secret,
                             algorithms=['HS256'])
    except Exception as exc:
        logger.info('SSO webhook signature rejected: %s', exc)
        return False

    # PyJWT enforces `exp` when present but accepts a token without one.
    # A token that never expires is a permanent credential sitting in whatever
    # log or proxy saw it once, so require the claim explicitly.
    exp = payload.get('exp')
    if not exp or int(exp) < int(time.time()):
        return False
    return True
