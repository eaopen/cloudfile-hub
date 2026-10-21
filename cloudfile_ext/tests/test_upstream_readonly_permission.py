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
    marker = Mock()
    # 24f9f09 起入口在 native 无直接授权时会问一次"是否有已注册的 V2 hook"，
    # 再由模块级 helper 裁决实际用户/路径。两者都要在 namespace 里存在，否则
    # 抽出来的函数体会在 NameError 上失败而不是给出权限结论。
    checks_registered = Mock(return_value=False)

    def _path_permission(request, repo_id, path, permission):
        return hook(request.user.username, repo_id, path, permission)

    namespace = dict(seafile_api=api, _cf_check_permission=hook,
                     _cf_has_permission_checks=checks_registered,
                     _cloudfile_path_permission=_path_permission,
                     _cf_mark_permission_unavailable=marker,
                     PERMISSION_READ='r', PERMISSION_READ_WRITE='rw',
                     PERMISSION_INVISIBLE='invisible',
                     SearpcError=RuntimeError, logger=Mock())
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), 'exec'),
         namespace)
    request = SimpleNamespace(user=SimpleNamespace(username='user@example.com'))
    return namespace['check_folder_permission'], request, api, hook


@pytest.fixture
def permission_marker(permission_entry):
    return permission_entry[0].__globals__['_cf_mark_permission_unavailable']


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


def test_rpc_error_fails_closed(permission_entry, permission_marker):
    check, request, api, hook = permission_entry
    api.check_permission_by_path.side_effect = RuntimeError('RPC unavailable')
    assert check(request, 'repo', '/private') is None
    hook.assert_not_called()
    # Still a denial here, but marked so the response middleware publishes 503
    # with a distinguishable code instead of a false 403 "Permission denied."
    permission_marker.assert_called_once_with(request)


def test_only_an_rpc_failure_marks_the_request(permission_entry, permission_marker):
    check, request, api, hook = permission_entry
    api.check_permission_by_path.return_value = None
    api.get_repo_status.return_value = 0
    assert check(request, 'repo', '/private') is None
    permission_marker.assert_not_called()


def test_registered_v2_hook_adjudicates_a_shared_directory_entry(permission_entry):
    """V2 注册了 hook 时，native 的"无直接授权"不再等于拒绝。

    共享目录用户正是这种情况：CE 只返回空，实际路径资格由 Authority 判定。
    这里锁住"问了 hook 并按它的结论返回"，避免以后又把空 native 当成终局。
    """
    check, request, api, hook = permission_entry
    api.check_permission_by_path.return_value = None
    api.get_repo_status.return_value = 0
    check.__globals__['_cf_has_permission_checks'].return_value = True
    assert check(request, 'repo', '/shared') == 'r'
    hook.assert_called_once_with('user@example.com', 'repo', '/shared', 'r')
