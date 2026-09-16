# -*- coding: utf-8 -*-
"""Browser entry point for the local-app install/help page.

This page exists for users who have not yet installed the Chrome extension or
the native agent. It is gated by CF_ENABLE_LOCAL_APP -- if local open/edit is
off, the help page has nothing to describe and 404s like the other capability
pages.
"""

from django.http import Http404
from django.shortcuts import render

from seahub.auth.decorators import login_required

from cloudfile_ext.features import is_enabled


@login_required
def local_app_help_page(request):
    if not is_enabled('CF_ENABLE_LOCAL_APP'):
        raise Http404
    return render(request, 'cloudfile_ext/local_app_help.html')
