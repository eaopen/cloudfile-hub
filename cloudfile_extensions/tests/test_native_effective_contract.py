"""The EAP permission gate must use current native policy without widening it."""
import ast
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from cloudfile_extensions.common.errors import ContractError, invalid
from cloudfile_extensions.resources.paths import resource_ref

REPO = '11111111-1111-4111-8111-111111111111'
SOURCE = Path(__file__).resolve().parents[1] / 'authorization/native_http.py'


class Params(dict):
    def getlist(self, key):
        return [self[key]] if not isinstance(self[key], list) else self[key]


def load(monkeypatch, permission, *, location_permission=None, root='/folder'):
    from cloudfile_extensions.authorization import directory_access
    current = SimpleNamespace(native_permission=None, inspect_policy=Mock(return_value={
        'effective_permission': permission, 'can_manage': True}))
    resolver = Mock(return_value={'permission': location_permission or permission, 'root_path': root})
    monkeypatch.setattr(directory_access, 'DirectoryAccessService', lambda value:
        SimpleNamespace(resolve=resolver) if value is current else None)
    names = {'NativeEffectiveView', 'NativeEffectiveContractView'}
    nodes = [n for n in ast.parse(SOURCE.read_text()).body if isinstance(n, ast.ClassDef) and n.name in names]
    env = dict(__name__='cloudfile_extensions.authorization.native_http', APIView=object, TokenAuthentication=object, SessionAuthentication=object,
        IsAuthenticated=object, resource_ref=resource_ref, invalid=invalid, ContractError=ContractError,
        response=lambda request, operation: operation(current))
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(SOURCE), 'exec'), env)
    request = SimpleNamespace(GET=Params(repo_id=REPO, path='/folder/child', kind='dir'))
    return env['NativeEffectiveContractView'](), env['NativeEffectiveView'](), request, current, resolver


@pytest.mark.parametrize('permission', ['r', 'rw', 'none', 'invisible'])
def test_eap_booleans_follow_native_content_not_management(monkeypatch, permission):
    view, legacy, request, current, resolver = load(monkeypatch, permission)
    result = view.get(request)
    assert result == dict(permission=permission if permission in ('r', 'rw') else None,
        read=permission in ('r', 'rw'), write=permission == 'rw', visible=permission in ('r', 'rw'),
        qualified_root='/folder' if permission in ('r', 'rw') else None)
    current.inspect_policy.assert_called_once_with(dict(request.GET))
    assert resolver.call_count == (1 if permission in ('r', 'rw') else 0)
    assert legacy.get(request)['effective_permission'] == permission


def test_second_scoped_read_can_revoke_write_before_response(monkeypatch):
    view, _, request, _, _ = load(monkeypatch, 'rw', location_permission='r')
    assert view.get(request)['write'] is False


@pytest.mark.parametrize('failure', [ContractError('POLICY_UNAVAILABLE', 'unavailable', 503), RuntimeError('offline')])
def test_policy_failure_is_never_an_allow_or_legacy_fallback(monkeypatch, failure):
    view, _, request, current, resolver = load(monkeypatch, 'rw')
    current.inspect_policy.side_effect = failure
    with pytest.raises(type(failure)):
        view.get(request)
    resolver.assert_not_called()


def test_unknown_native_permission_fails_closed(monkeypatch):
    view, _, request, _, resolver = load(monkeypatch, 'admin')
    with pytest.raises(ContractError) as error:
        view.get(request)
    assert error.value.status == 503
    resolver.assert_not_called()


def test_actor_query_cannot_select_another_subject(monkeypatch):
    view, _, request, current, _ = load(monkeypatch, 'rw')
    request.GET['user_id'] = 'other'
    with pytest.raises(ContractError):
        view.get(request)
    current.inspect_policy.assert_not_called()


def test_library_eligible_diagnostic_does_not_require_pending_birth_state(monkeypatch):
    view, _, request, current, resolver = load(monkeypatch, 'rw')
    current.native_permission = 'r'
    resolver.side_effect = ContractError('PATH_STATE_PENDING', 'birth pending', 503)
    result = view.get(request)
    assert result['qualified_root'] == '/' and result['write'] is True
    resolver.assert_not_called()
