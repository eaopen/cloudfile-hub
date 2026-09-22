# -*- coding: utf-8 -*-
"""Endpoints and pages that are part of the CloudFile framework itself."""

from django.shortcuts import render
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from seahub.api2.authentication import TokenAuthentication
from seahub.api2.throttling import UserRateThrottle
from seahub.auth.decorators import login_required

from cloudfile_ext.features import enabled_features
from cloudfile_ext.registry import registry


class CloudFileFeaturesView(APIView):
    """Report which CF_ENABLE_* switches are on, and which providers exist.

    The frontend uses this to hide entry points for capabilities that are not
    deployed. It is a convenience, not a security boundary -- every switch is
    re-checked server side, and directory ACL is enforced all the way down in
    seafile-server.

    This lives in an endpoint rather than a template context processor because
    Seahub's TEMPLATES context_processors list is nested inside a dict, which
    the EXTRA_* settings mechanism cannot append to; using an endpoint keeps
    the number of patched upstream files at two.
    """

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    def get(self, request):
        # `providers` is what makes a misconfiguration diagnosable without
        # shell access: it reports the selected name next to the names that
        # are actually registered, which is the difference between "search is
        # broken" and "CF_PROVIDER_SEARCH names a capability that is off".
        return Response({
            'features': enabled_features(),
            'providers': registry.providers.describe(),
            'menu': registry.menu,
        })


@login_required
def cloudfile_admin_page(request):
    """Serve the capability-overview page that reports the CF_ENABLE_* state.

    The page existed as a webpack entry (`cloudfileAdmin`) with no template and
    no route, so the bundle was built and could never load -- the only way to
    read a deployment's switch state back was the API by hand. This view and
    `admin.html` close that: the page renders exactly what
    ``/api/v2.1/cloudfile/features/`` already returns to any authenticated
    user, so it exposes nothing new and needs no staff gate of its own.
    """
    return render(request, 'cloudfile_ext/admin.html')
