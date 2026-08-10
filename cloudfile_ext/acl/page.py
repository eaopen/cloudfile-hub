# -*- coding: utf-8 -*-
"""Page view for the directory ACL management UI.

The API endpoints (DirACLView / DirACLEffectiveView) live in apis.py and
admin_apis.py -- this view only serves the React SPA page that hosts them.
"""

from django.shortcuts import render
from seahub.auth.decorators import login_required


@login_required
def acl_page(request):
    """Render the directory ACL management page.

    Query parameters:
        repo_id: hex string, the library whose ACL rules to edit.
        path:    (optional) folder path within the library, default "/".
    """
    repo_id = request.GET.get('repo_id', '')
    path = request.GET.get('path', '/')
    return render(request, 'cloudfile_acl_react.html', {
        'repo_id': repo_id,
        'path': path,
    })
