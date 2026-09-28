# -*- coding: utf-8 -*-
"""Browser entry point for owner-managed directory ACL rules."""

from django.http import Http404
from django.shortcuts import render

from seahub.auth.decorators import login_required

from cloudfile_ext.features import is_enabled


@login_required
def acl_page(request):
    if not is_enabled('CF_ENABLE_DIR_ACL'):
        raise Http404
    return render(request, 'cloudfile_ext/acl.html')
