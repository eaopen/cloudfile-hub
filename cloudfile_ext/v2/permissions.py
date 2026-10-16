"""The single protected-request gate for CloudFile V2 resources.

Every CloudFile view answers through this permission class, so the CloudFile
surface cannot drift into a second authorization rule: no ready subject, no
CloudFile answer. A deployment without a configured Directory keeps its native
behavior, and native CE endpoints are never gated here.
"""
from rest_framework.exceptions import APIException
from rest_framework.permissions import BasePermission

from .errors import IdentityUnavailable, SubjectNotBound
from .runtime import require_ready


class SubjectUnbound(APIException):
    status_code = 403
    default_code = 'CF_SUBJECT_MISSING'
    default_detail = 'The native account has no trusted stable UID.'


class SubjectUnavailable(APIException):
    status_code = 503
    default_code = 'CF_SUBJECT_UNAVAILABLE'
    default_detail = 'The CloudFile subject is not ready; authorization is unavailable.'


class SubjectReady(BasePermission):
    """Require a ready UID subject before serving any CloudFile resource.

    Inside the configured TTL this is a reuse of the published subject; once the
    TTL is gone the projector re-queries the Directory. A missing native UID
    binding is 403 and any failed refresh is 503, so stale native GroupUser rows
    can never authorize a CloudFile request.
    """

    message = 'The CloudFile subject is not ready.'

    def has_permission(self, request, view):
        user = getattr(request, 'user', None)
        if user is None or not getattr(user, 'is_authenticated', False):
            return False
        try:
            require_ready(user.username)
        except SubjectNotBound:
            raise SubjectUnbound() from None
        except IdentityUnavailable:
            raise SubjectUnavailable() from None
        return True
