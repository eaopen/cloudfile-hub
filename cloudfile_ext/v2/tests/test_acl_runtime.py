"""Same authority for native members and directory-only virtual views."""
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock
from cloudfile_ext.v2.acl_policy import Principal, Rule, resolve
from cloudfile_ext.v2.acl_runtime import Authority

RID = '00000000-0000-4000-8000-000000000001'
P = Principal('etech', 'uid')


class RuntimeTests(TestCase):
    def authority(self, base=None, share=True, permission='rw', inherit=True):
        rule = Rule(RID, '/projects/shared', 'etech', 'user', 'user', 'uid', permission, inherit, share)
        rules = Mock()
        rules.candidates.side_effect = lambda repo, path, principal: [(rule, 'v')] if path.startswith(rule.path) else []
        rules.shared.return_value = [(rule, 'v')]
        api = Mock()
        api.get_repo.return_value = SimpleNamespace(is_virtual=False)
        api.get_repo_status.return_value = 0
        api.check_permission.return_value = base
        api.get_dir_id_by_path.return_value = 'directory-object'
        return Authority('native@auth.local', principal=P, rules=rules, api=api)

    def test_directory_only_access_requires_both_share_and_permission(self):
        auth = self.authority()
        for path in ('/projects/shared', '/projects/shared/sub'):
            result = auth.effective(RID, path)
            self.assertTrue(result.can_read)
            self.assertEqual(result.qualified_root, '/projects/shared')
        self.assertTrue(auth.effective(RID, '/projects/shared/file', 'file').can_write)
        for path in ('/', '/projects', '/projects/sibling', '/projects/shared-other'):
            self.assertFalse(auth.effective(RID, path).can_read)
        self.assertFalse(self.authority(share=False).effective(RID, '/projects/shared').can_read)

    def test_library_member_keeps_library_root(self):
        auth = self.authority(base='r')
        self.assertEqual(auth.effective(RID, '/').qualified_root, '/')
        self.assertEqual(auth.effective(RID, '/projects/shared').qualified_root, '/')
        self.assertTrue(auth.effective(RID, '/projects/shared').can_write)

    def test_listing_is_bounded_and_root_is_not_parent_corridor(self):
        auth = self.authority()
        auth.api.list_dir_by_dir_id.return_value = [SimpleNamespace(obj_name='file.txt', mode=0o100644)]
        result = auth.entries(RID, '/projects/shared')
        self.assertEqual(result['root_path'], '/projects/shared')
        self.assertEqual(result['data'][0]['path'], '/projects/shared/file.txt')
        auth.api.list_dir_by_dir_id.assert_called_once_with(RID, 'directory-object', 0, 51)
        for path in ('/', '/projects', '/projects/sibling'):
            with self.assertRaises(PermissionError):
                auth.entries(RID, path)

    def test_hard_readonly_and_denial_use_the_same_algorithm(self):
        auth = self.authority()
        auth.api.get_repo_status.return_value = 1
        self.assertTrue(auth.effective(RID, '/projects/shared').can_read)
        self.assertFalse(auth.effective(RID, '/projects/shared').can_write)
        auth = self.authority(base='rw', share=False, permission='none')
        self.assertFalse(auth.effective(RID, '/projects/shared').can_read)

    def test_stale_or_inactive_principal_denied(self):
        auth = self.authority()
        auth.principal = Principal('etech', 'uid', ready=False)
        self.assertFalse(auth.effective(RID, '/projects/shared').can_read)
        auth.principal = Principal('etech', 'uid', active=False)
        self.assertFalse(auth.effective(RID, '/projects/shared').can_write)

    def test_subject_share_does_not_grant_everyone(self):
        auth = self.authority()
        auth.principal = Principal('etech', 'another-user')
        self.assertFalse(auth.effective(RID, '/projects/shared').can_read)
        self.assertEqual(auth.shared_roots(), [])

    def test_listing_hides_denied_child(self):
        auth = self.authority()
        allow = auth.store.shared.return_value[0]
        denied = Rule(RID, '/projects/shared/secret', 'etech', 'user', 'user', 'uid', 'invisible')
        auth.store.candidates.side_effect = lambda repo,path,p: [allow] + ([(denied,'v')] if path.endswith('/secret') else [])
        auth.api.list_dir_by_dir_id.return_value = [SimpleNamespace(obj_name='secret', mode=0o040755)]
        self.assertEqual(auth.entries(RID, '/projects/shared')['data'], [])
