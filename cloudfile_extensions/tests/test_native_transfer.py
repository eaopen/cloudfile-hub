"""Native read links retain exact user credentials and guarded transport."""
import hashlib
import json
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from cloudfile_extensions.authorization import native_transfer as transfer
from cloudfile_extensions.common.errors import ContractError

REPO = '11111111-1111-4111-8111-111111111111'
TICKET = '22222222-2222-4222-8222-222222222222'


class Params(dict):
    def getlist(self, key):
        value = self[key]
        return value if isinstance(value, list) else [value]


@pytest.fixture
def native(monkeypatch):
    class Token:
        user = 'employee@auth.local'
        key = 'a' * 40
    class SessionAuthentication:
        pass
    monkeypatch.setitem(sys.modules, 'seahub.api2.models', SimpleNamespace(Token=Token))
    monkeypatch.setitem(sys.modules, 'rest_framework.authentication', SimpleNamespace(SessionAuthentication=SessionAuthentication))
    monkeypatch.setitem(sys.modules, 'seahub.utils', SimpleNamespace(get_fileserver_root=lambda: 'https://files.invalid/cfhttp/'))
    monkeypatch.setitem(sys.modules, 'seahub.auth', SimpleNamespace(SESSION_KEY='user', BACKEND_SESSION_KEY='backend'))
    request = SimpleNamespace(auth=Token(), user=SimpleNamespace(username=Token.user),
        GET=Params(p='/目录/a +%.txt'), _request=SimpleNamespace(read=lambda size: b''))
    current = SimpleNamespace(consume=Mock(), preparation=SimpleNamespace(actor='uid-1',
        state=SimpleNamespace(provider='company'),
        contexts=SimpleNamespace(current=Mock(return_value={'context_epoch': 'epoch'}))))
    issue = Mock(return_value=TICKET)
    monkeypatch.setattr(transfer, 'resolve_and_issue_native_ticket', issue)
    return request, current, issue, Token, SessionAuthentication


def test_token_link_uses_current_actor_and_only_private_digest(native):
    request, current, issue, _, _ = native
    url = transfer.download_url(request, current, REPO)
    assert url == 'https://files.invalid/cfhttp/cloudfile/files/' + TICKET + '/a%20%2B%25.txt'
    args = issue.call_args.args
    assert args[:4] == (REPO, '/目录/a +%.txt', 'download', request.user.username)
    conditions = json.loads(args[4])
    assert conditions['context']['userId'] == 'uid-1'
    assert conditions['native_read_token'] == {'sha256': hashlib.sha256(('a' * 40).encode()).hexdigest()}
    assert request.auth.key not in args[4] and request.auth.key not in url
    assert conditions['directory_access'] is True
    current.consume.assert_called_once()


@pytest.mark.parametrize('query', [dict(p='/a', userId='other'), dict(p=['/a', '/b']),
    dict(p='/a', reuse='1'), dict(p='/a', op='downloadblks'), {}, dict(p='/../a')])
def test_bad_query_never_issues_ticket(native, query):
    request, current, issue, _, _ = native
    request.GET = Params(query)
    with pytest.raises(ContractError):
        transfer.download_url(request, current, REPO)
    issue.assert_not_called()
    current.consume.assert_not_called()


def test_deny_and_unavailable_context_never_issue(native):
    request, current, issue, _, _ = native
    current.consume.side_effect = ContractError('ACCESS_DENIED', 'Denied', 403)
    with pytest.raises(ContractError) as error:
        transfer.download_url(request, current, REPO)
    assert error.value.status == 403
    issue.assert_not_called()
    current.consume.side_effect = None
    current.preparation.contexts.current.return_value = None
    with pytest.raises(ContractError) as error:
        transfer.download_url(request, current, REPO)
    assert error.value.status == 503
    issue.assert_not_called()


def test_mismatched_or_unknown_token_never_becomes_session(native):
    request, current, issue, _, _ = native
    request.auth.user = 'different@auth.local'
    with pytest.raises(ContractError) as error:
        transfer.download_url(request, current, REPO)
    assert error.value.status == 403
    request.auth = object()
    with pytest.raises(ContractError) as error:
        transfer.download_url(request, current, REPO)
    assert error.value.status == 503
    current.consume.assert_not_called()
    issue.assert_not_called()


def test_only_authenticated_persisted_oauth_session_becomes_browser_proof(native):
    request, _, _, _, auth = native
    class Session(dict):
        session_key = 's' * 32
    request.auth = None
    request.successful_authenticator = auth()
    request.session = Session(user=request.user.username,
        backend='seahub.oauth.backends.OauthRemoteUserBackend')
    assert transfer.read_proof(request) == {'browser_session': {'session_key': 's' * 32}}
    request.session['user'] = 'another@auth.local'
    with pytest.raises(ContractError) as error:
        transfer.read_proof(request)
    assert error.value.status == 401
