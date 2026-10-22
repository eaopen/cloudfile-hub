"""V2 PermissionService facade must use the current path Authority."""
from unittest.mock import Mock, patch
from cloudfile_ext.permissions import PermissionService


def test_facade_uses_v2_path_not_native_caller_claim():
    result = Mock(permission='r', can_read=True)
    with patch('cloudfile_ext.v2.acl_runtime.Authority') as authority:
        authority.return_value.effective.return_value = result
        assert PermissionService.effective_perm('user', 'repo', '/A', 'rw') == 'r'
        authority.return_value.effective.assert_called_once_with('repo', '/A', 'dir')
        assert authority.call_args.args == ('user',)


def test_facade_denial_and_unavailable_fail_closed():
    with patch('cloudfile_ext.v2.acl_runtime.Authority') as authority:
        authority.return_value.effective.return_value = Mock(permission='invisible', can_read=False)
        assert PermissionService.effective_perm('user', 'repo', '/A', 'rw') is None
        authority.side_effect = RuntimeError('ACL offline')
        assert PermissionService.effective_perm('user', 'repo', '/A', 'rw') is None


def test_only_ce_repo_admin_can_manage():
    with patch('seahub.share.utils.is_repo_admin', return_value=True):
        assert PermissionService.can_manage('user', 'repo', '/A')
    with patch('seahub.share.utils.is_repo_admin', return_value=False):
        assert not PermissionService.can_manage('user', 'repo', '/A')
