# -*- coding: utf-8 -*-
"""React entry point for the external-source read-only browser."""

from django.http import Http404
from django.shortcuts import render

from seahub.auth.decorators import login_required

from cloudfile_ext.features import is_enabled


@login_required
def external_sources_page(request):
    """Serve no page at all while the capability is disabled."""
    if not is_enabled('CF_ENABLE_EXTERNAL_SOURCES'):
        raise Http404
    return render(request, 'cloudfile_ext/external_sources.html')
