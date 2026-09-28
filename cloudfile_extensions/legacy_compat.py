"""Narrow HTTP compatibility for the delivered CloudFile ACL implementation."""

from uuid import UUID

from rest_framework import status

from cloudfile_ext.acl.apis import DirACLEffectiveView
from seahub.api2.utils import api_error


class LegacyEffectivePermission(DirACLEffectiveView):
    """Accept the new query shape and let the legacy authenticated view decide."""

    def get(self, request):
        repo_id = request.GET.get('repo_id')
        try:
            if str(UUID(repo_id)) != repo_id or request.GET.get('kind') != 'dir':
                raise ValueError('invalid effective-permission query')
        except (TypeError, ValueError, AttributeError):
            return api_error(status.HTTP_400_BAD_REQUEST, 'Invalid effective-permission query.')
        return super().get(request, repo_id)
