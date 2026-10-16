"""V2 ACL reads and guarded management. No endpoint enables protected publication."""
from dataclasses import asdict
import time

import jwt
from django.conf import settings
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from seahub.api2.authentication import TokenAuthentication, SessionAuthentication
from seahub.api2.utils import JWT_PRIVATE_KEY

from .permissions import SubjectReady
from .acl_policy import PolicyError, Rule
from .acl_runtime import Authority, store
from .acl_store import uuid


def response(data, status=200):
    value = Response(data, status=status)
    value['Cache-Control'] = 'no-store'
    return value


def failure(error):
    if isinstance(error, (ValueError, TypeError, KeyError, PolicyError)):
        return response({'code': 'INVALID_ACL_REQUEST'}, 400)
    if isinstance(error, PermissionError):
        return response({'code': 'ACL_DENIED'}, 403)
    return response({'code': 'ACL_UNAVAILABLE'}, 503)


class AuthenticatedACL(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, SubjectReady,)


class EffectivePermission(AuthenticatedACL):
    def get(self, request):
        try:
            args = request.query_params
            if set(args) - {'repo_id', 'path', 'kind'} or any(len(args.getlist(k)) != 1 for k in args):
                raise ValueError()
            decision = Authority(request.user.username).effective(args['repo_id'], args['path'], args.get('kind', 'dir'))
            return response(dict(**asdict(decision), read=decision.can_read, write=decision.can_write,
                                 visible=decision.visible, protected_publication=False))
        except Exception as error:
            return failure(error)


class SharedDirectories(AuthenticatedACL):
    def get(self, request):
        try:
            if request.query_params:
                raise ValueError()
            return response({'data': Authority(request.user.username).shared_roots(), 'protected_publication': False})
        except Exception as error:
            return failure(error)


class DirectoryRules(AuthenticatedACL):
    # Minimal native administrator maintenance read. rw never means manage.
    permission_classes = (IsAdminUser, SubjectReady,)

    def get(self, request):
        try:
            args = request.query_params
            if set(args) != {'repo_id', 'path'} or any(len(args.getlist(k)) != 1 for k in args):
                raise ValueError()
            rows = store().list_path(args['repo_id'], args['path'], settings.CF_ACL_PROVIDER)
            return response({'data': [dict(**asdict(rule), revision=revision) for rule, revision in rows]})
        except Exception as error:
            return failure(error)

    def post(self, request):
        # No settings flag can accidentally certify full C/Go enforcement.
        # The internal CAS writer is ready for the sole integrator, but enabling
        # public writes requires scoped machine credentials + runtime acceptance.
        return response({'code': 'ACL_PUBLICATION_BLOCKED'}, 503)

    put = post
    delete = post


class NativeACLCheck(APIView):
    """Existing native internal JWT, trusted username, bounded exact paths.

    This is a permission check, never a bearer grant. Native code invokes it
    anew at reads and under Branch(master) at final commit.
    """
    authentication_classes = ()
    permission_classes = (AllowAny,)

    def post(self, request):
        try:
            header = request.headers.get('Authorization', '').split()
            if len(header) != 2 or header[0] != 'Token' or not JWT_PRIVATE_KEY:
                raise PermissionError()
            claims = jwt.decode(header[1], JWT_PRIVATE_KEY, algorithms=['HS256'], options={'require': ['exp', 'is_internal']})
            if claims.get('is_internal') is not True or claims['exp'] > time.time() + 310:
                raise PermissionError()
        except Exception:
            return response({'code': 'NATIVE_AUTH_REQUIRED'}, 403)
        try:
            data = request.data
            if set(data) != {'username', 'repo_id', 'checks'}:
                raise ValueError()
            uuid(data['repo_id'])
            if not isinstance(data['username'], str) or not data['username'] or len(data['username']) > 255:
                raise ValueError()
            checks = data['checks']
            if not isinstance(checks, list) or not 1 <= len(checks) <= 4096:
                raise ValueError()
            authority = Authority(data['username'])
            for check in checks:
                if set(check) != {'path', 'kind', 'action'} or check['action'] not in ('read', 'write'):
                    raise ValueError()
                decision = authority.effective(data['repo_id'], check['path'], check['kind'])
                if not (decision.can_read if check['action'] == 'read' else decision.can_write):
                    raise PermissionError()
            return response({'allowed': True, 'contract': 'cf-acl-v1'})
        except Exception as error:
            return failure(error)


class DirectoryEntries(AuthenticatedACL):
    def get(self, request):
        try:
            args = request.query_params
            if set(args) - {'repo_id', 'path', 'offset', 'limit'} or any(len(args.getlist(k)) != 1 for k in args):
                raise ValueError()
            result = Authority(request.user.username).entries(args['repo_id'], args['path'],
                offset=int(args.get('offset', '0')), limit=int(args.get('limit', '50')))
            return response(result)
        except FileNotFoundError:
            return response({'code': 'DIRECTORY_NOT_FOUND'}, 404)
        except Exception as error:
            return failure(error)
