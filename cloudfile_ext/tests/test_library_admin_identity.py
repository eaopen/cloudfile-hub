"""An alias must never move a grant to a changed OAuth/native identity."""
from types import SimpleNamespace
import unittest
from cloudfile_ext.library_admin_identity import check_binding


class VerifiedAliasTests(unittest.TestCase):
    def setUp(self):
        self.alias = '10220942@auth.local'
        self.binding = dict(native_user='opaque@auth.local', employee_no='10220942',
                            user_id='381', provider='test-provider', oauth_subject='stable-sub')
        self.profile = SimpleNamespace(user='opaque@auth.local', login_id='10220942')
        self.links = [('opaque@auth.local', 'test-provider', 'stable-sub')]

    def check(self, owner=None):
        return check_binding(self.alias, self.binding, self.profile, self.links, owner)

    def test_existing_account_and_uid_profile_are_supported(self):
        self.assertEqual(self.check(), 'opaque@auth.local')
        self.profile.login_id = '381'
        self.assertEqual(self.check(), 'opaque@auth.local')

    def test_oauth_uid_is_not_replaced_by_business_uid(self):
        self.links = [('opaque@auth.local', 'test-provider', '381')]
        with self.assertRaises(ValueError): self.check()

    def test_alias_collision_is_rejected(self):
        with self.assertRaises(ValueError): self.check('another@auth.local')

    def test_profile_reassignment_is_rejected(self):
        self.profile.login_id = '999'
        with self.assertRaises(ValueError): self.check()

    def test_missing_or_duplicate_binding_is_rejected(self):
        for links in ([], self.links * 2):
            self.links = links
            with self.assertRaises(ValueError): self.check()

    def test_unverified_alias_is_rejected(self):
        self.alias = '381@auth.local'
        with self.assertRaises(ValueError): self.check()
