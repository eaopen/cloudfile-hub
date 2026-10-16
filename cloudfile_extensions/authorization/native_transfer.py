"""Native user authentication to existing guarded single-file read tickets."""
import hashlib
import json
import re
from urllib.parse import quote

from ..common.errors import ContractError, invalid
from ..identity.ticket_transport import resolve_and_issue_native_ticket
from ..resources.paths import resource_ref


def read_proof(request):
    # Only the actual DRF-authenticated v1 model may become a token proof.
    # Parsing Authorization here would let a client select a different actor.
    from seahub.api2.models import Token
    from rest_framework.authentication import SessionAuthentication
    token = request.auth
    if type(token) is Token:
        if token.user != request.user.username or not re.fullmatch('[0-9a-f]{40}', token.key):
            raise ContractError('ACCESS_DENIED', 'Native token identity changed', 403)
        return {'native_read_token': {'sha256': hashlib.sha256(token.key.encode('ascii')).hexdigest()}}
    if token is not None:
        raise ContractError('POLICY_UNAVAILABLE', 'This native token kind is not supported for transfer', 503)
    from seahub.auth import SESSION_KEY, BACKEND_SESSION_KEY
    session = request.session
    if (not isinstance(request.successful_authenticator, SessionAuthentication)
            or session.get(BACKEND_SESSION_KEY) != 'seahub.oauth.backends.OauthRemoteUserBackend'
            or session.get(SESSION_KEY) != request.user.username
            or not isinstance(session.session_key, str)
            or not re.fullmatch('[0-9a-z]{32}', session.session_key)):
        raise ContractError('AUTHENTICATION_REQUIRED', 'Persisted native OAuth session required', 401)
    return {'browser_session': {'session_key': session.session_key}}


def download_url(request, current, repo_id):
    from seahub.utils import get_fileserver_root
    params = request.GET
    if (set(params) - {'p', 'op', 'reuse'} or 'p' not in params
            or any(len(params.getlist(key)) != 1 for key in params)
            or params.get('op', 'download') != 'download'
            or params.get('reuse', '0') != '0' or request._request.read(1)):
        raise invalid('An exact single-use file download is required')
    ref = resource_ref(dict(repo_id=repo_id, path=params['p'], kind='file'))
    proof = read_proof(request)
    # Release preflight SQL locks before RPC. Server independently repeats the
    # account, identity, context, ACL, credential and exact native target checks.
    current.consume(ref, lambda cursor, target: None)
    preparation = current.preparation
    actor, provider = preparation.actor, preparation.state.provider
    context = preparation.contexts.current(actor)
    if context is None:
        raise ContractError('SUBJECT_UNAVAILABLE', 'Current subject unavailable', 503)
    conditions = dict(path=ref['path'], directory_access=True,
        context=dict(provider=provider, userId=actor, epoch=context['context_epoch']),
        scopes=[dict(type='provider', provider=provider, external_id=provider),
            dict(type='user', provider=provider, external_id=actor),
            dict(type='repo', provider='cloudfile', external_id=repo_id)], **proof)
    encoded = json.dumps(conditions, ensure_ascii=False, separators=(',', ':'))
    if len(encoded.encode('utf-8')) > 16384:
        raise invalid('Read conditions exceed budget')
    ticket = resolve_and_issue_native_ticket(repo_id, ref['path'], 'download',
        request.user.username, encoded, token_bound='native_read_token' in proof)
    return get_fileserver_root().rstrip('/') + '/cloudfile/files/' + ticket + '/' + quote(ref['path'].rsplit('/', 1)[-1], safe='')
