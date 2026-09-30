"""Exercise the patched upstream permission entry without a native runtime."""

import ast
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest


@pytest.fixture
def permission_entry():
    # Isolate the real entry point: importing Seahub needs native RPC services.
    source = Path(__file__).resolve().parents[2] / 'seahub/views/__init__.py'
    tree = ast.parse(source.read_text())
    function = next(node for node in tree.body
                    if isinstance(node, ast.FunctionDef)
                    and node.name == 'check_folder_permission')
    api = Mock()
    hook = Mock(side_effect=lambda username, repo_id, path, permission: permission)
    namespace = dict(seafile_api=api, _cf_check_permission=hook,
                     PERMISSION_READ='r', PERMISSION_INVISIBLE='invisible',
                     SearpcError=RuntimeError, logger=Mock())
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), 'exec'),
         namespace)
    request = SimpleNamespace(user=SimpleNamespace(username='user@example.com'))
    return namespace['check_folder_permission'], request, api, hook


@pytest.mark.parametrize('read_only', [0, 1])
@pytest.mark.parametrize('native', [None, '', 'invisible'])
def test_missing_native_permission_never_grants_access(permission_entry, read_only, native):
    check, request, api, hook = permission_entry
    api.check_permission_by_path.return_value = native
    api.get_repo_status.return_value = read_only
    assert check(request, 'repo', '/private') is None
    hook.assert_not_called()


@pytest.mark.parametrize('native', ['r', 'rw'])
@pytest.mark.parametrize('read_only, expected', [(0, None), (1, 'r')])
def test_native_permission_is_downgraded_before_cloudfile_hook(
        permission_entry, native, read_only, expected):
    check, request, api, hook = permission_entry
    api.check_permission_by_path.return_value = native
    api.get_repo_status.return_value = read_only
    expected = expected or native
    assert check(request, 'repo', '/private') == expected
    hook.assert_called_once_with('user@example.com', 'repo', '/private', expected)


def test_cloudfile_denial_still_applies_to_readonly_repo(permission_entry):
    check, request, api, hook = permission_entry
    api.check_permission_by_path.return_value = 'rw'
    api.get_repo_status.return_value = 1
    hook.side_effect = lambda *args: None
    assert check(request, 'repo', '/private') is None
    hook.assert_called_once_with('user@example.com', 'repo', '/private', 'r')


def test_missing_username_does_not_query_permissions(permission_entry):
    check, request, api, hook = permission_entry
    request.user.username = ''
    assert check(request, 'repo', '/private') is None
    api.check_permission_by_path.assert_not_called()
    hook.assert_not_called()


def test_rpc_error_fails_closed(permission_entry):
    check, request, api, hook = permission_entry
    api.check_permission_by_path.side_effect = RuntimeError('RPC unavailable')
    assert check(request, 'repo', '/private') is None
    hook.assert_not_called()
