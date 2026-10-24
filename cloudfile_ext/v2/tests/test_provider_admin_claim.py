"""Security-sensitive enterprise admin input never comes from role names."""
import unittest

from cloudfile_ext.v2.errors import IdentityUnavailable
from cloudfile_ext.v2.provider_admin import trusted_super_admin


class TrustedAdministratorClaimTests(unittest.TestCase):
    def test_verified_active_enterprise_superadmin_claim(self):
        self.assertTrue(trusted_super_admin(
            {'userId': 'user-9', 'status': 'active', 'super_admin': True}, 'user-9',
            require_claim=True))

    def test_ordinary_user_and_maintenance_role_never_imply_superadmin(self):
        user = {'userId': 'user-1', 'status': 'active', 'super_admin': False,
                'roles': [{'namespace': 'role', 'external_id': 'admin'},
                          {'namespace': 'role', 'external_id': 'maintenance'}]}
        self.assertFalse(trusted_super_admin(user, 'user-1', require_claim=True))
        self.assertFalse(trusted_super_admin(
            {'userId': 'user-1', 'status': 'active',
             'attributes': {'employee_no': 'admin'}}, 'user-1'))

    def test_claim_absence_allowed_only_for_legacy_non_admin_mode(self):
        data = {'userId': 'user-1', 'status': 'active'}
        self.assertFalse(trusted_super_admin(data, 'user-1'))
        with self.assertRaises(IdentityUnavailable):
            trusted_super_admin(data, 'user-1', require_claim=True)

    def test_conflict_malformed_and_disabled_privileged_subject_fail_closed(self):
        cases = [
            ({'userId': 'other', 'status': 'active', 'super_admin': True}, 'user-9'),
            ({'userId': 'user-9', 'status': 'active', 'super_admin': 'true'}, 'user-9'),
            ({'userId': 'user-9', 'status': 'active', 'super_admin': 1}, 'user-9'),
            ({'userId': 'user-9', 'status': 'active', 'super_admin': None}, 'user-9'),
            ({'userId': 'user-9', 'status': 'disabled', 'super_admin': True}, 'user-9'),
            ({'userId': 'user-9', 'status': 'other', 'super_admin': False}, 'user-9'),
        ]
        for value, uid in cases:
            with self.subTest(value=value), self.assertRaises(IdentityUnavailable):
                trusted_super_admin(value, uid, require_claim=True)

    def test_disabled_user_carries_explicit_revocation_fact(self):
        self.assertFalse(trusted_super_admin(
            {'userId': 'user-9', 'status': 'disabled', 'super_admin': False},
            'user-9', require_claim=True))


if __name__ == '__main__':
    unittest.main()
