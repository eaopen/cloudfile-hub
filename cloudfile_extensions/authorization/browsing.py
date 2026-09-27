"""ACL filtering for the existing CE Web library and directory lists."""
from contextlib import nullcontext
from functools import wraps
import posixpath
from uuid import uuid4

from django.conf import settings
from rest_framework.response import Response

from ..common.errors import ContractError
from ..identity.read_ticket_http import native_download_actor
from ..identity.resources import LoginResources
from ..identity.session_authority import OIDCSessionAuthority
from .core import PolicyCore
from .read import ContentReadAuthority


def filter_entries(authority, entries, reference):
    """Keep only current readable entries and restrict their displayed permission."""
    result = []
    for entry in entries:
        try:
            permission = authority.consume(reference(entry),
                lambda cursor, target: 'rw' if authority.effective_access['write'] else 'r')
        except ContractError as error:
            if error.code != 'ACCESS_DENIED':
                raise
            continue
        item = dict(entry)
        if permission == 'r':
            item['permission'] = 'r'
        result.append(item)
    return result


def web_list(kind):
    """Opt in with the existing OIDC host resources; ordinary CE stays unchanged."""
    def decorate(view):
        @wraps(view)
        def guarded(self, request, *args, **kwargs):
            scope = getattr(settings, 'CLOUDFILE_OIDC_LOGIN_RESOURCE_SCOPE', None)
            resources = getattr(settings, 'CLOUDFILE_OIDC_LOGIN_RESOURCES', None)
            if scope is None and resources is None:
                return view(self, request, *args, **kwargs)
            request_id = str(uuid4())
            try:
                actor = native_download_actor(request)
                with (scope() if callable(scope) else nullcontext(resources)) as resources:
                    if not isinstance(resources, LoginResources):
                        raise ContractError('POLICY_UNAVAILABLE', 'Browsing authority is unavailable', 503)
                    session = OIDCSessionAuthority(resources)
                    session.check(request)
                    with resources.resources.preparation(actor.user_id, request_id) as preparation:
                        preparation.prepare(actor.user_id)
                        if preparation.state.username(actor.user_id) != actor.native_username:
                            raise ContractError('ACCESS_DENIED', 'Native identity changed', 403)
                        config = settings.CLOUDFILE_POLICY_CONFIG
                        authority = ContentReadAuthority(preparation, PolicyCore(config['core_library']),
                            request_id=request_id, cloud_mode=config['cloud_mode'])
                        if kind == 'directory':
                            # Rare recursive/ancestor/preview variants remain closed.
                            if (request.GET.get('recursive', '0') != '0'
                                    or request.GET.get('with_parents', 'false') != 'false'
                                    or request.GET.get('with_thumbnail', 'false') != 'false'):
                                raise ContractError('ACCESS_DENIED', 'Extended browsing is unavailable', 403)
                            repo = kwargs.get('repo_id') or args[0]
                            path = request.GET.get('p', '/').rstrip('/') or '/'
                            parent_permission = authority.consume(dict(repo_id=repo, path=path, kind='dir'),
                                lambda cursor, target: 'rw' if authority.effective_access['write'] else 'r')
                        response = view(self, request, *args, **kwargs)
                        if response.status_code == 200:
                            data = dict(response.data)
                            if kind == 'libraries':
                                data['repos'] = filter_entries(authority, data['repos'],
                                    lambda item: dict(repo_id=item['repo_id'], path='/', kind='dir'))
                            else:
                                data['dirent_list'] = filter_entries(authority, data['dirent_list'],
                                    lambda item: dict(repo_id=repo, kind=item['type'],
                                        path=posixpath.join(item['parent_dir'], item['name'])))
                                if parent_permission == 'r':
                                    data['user_perm'] = 'r'
                                # CE metadata enrichment is outside the v0.2 browse contract.
                                data.pop('metadata', None)
                            response.data = data
                    session.check(request)
            except ContractError as error:
                response = Response(error.response(request_id), status=error.status)
            except Exception:
                error = ContractError('POLICY_UNAVAILABLE', 'Browsing authority is unavailable', 503)
                response = Response(error.response(request_id), status=503)
            response['Cache-Control'] = 'no-store, max-age=0'
            response['Vary'] = 'Cookie, Authorization'
            response['X-Request-ID'] = request_id
            return response
        return guarded
    return decorate
