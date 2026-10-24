"""External administrator privilege is checked for each credential request."""
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock

from cloudfile_ext.v2.provider_admin_gate import (
    is_native_root, mask_unverified_staff, provider_admin_allowed,
)


def staff_user(username='employee@auth.local'):
    return SimpleNamespace(username=username, is_staff=True, is_superuser=False,
                           is_active=True, admin_role='default_admin')


class ProviderAdministratorGateTests(TestCase):
    def test_exact_native_root_remains_available_without_directory(self):
        for name in ('cfadmin', 'cfadmin@auth.local', 'cfadmin@etech.com'):
            fetch = Mock(side_effect=AssertionError('native root never queries Provider'))
            self.assertTrue(is_native_root(name, 'cfadmin'))
            self.assertTrue(provider_admin_allowed(name, 'cfadmin', fetch))
            self.assertTrue(provider_admin_allowed(name, None, fetch))
            fetch.assert_not_called()
        self.assertFalse(is_native_root('cfadmin@company.test', 'cfadmin'))
        self.assertFalse(is_native_root('cfadmin@auth.local', 'other-uid'))

    def test_verified_business_uid_allows_existing_staff(self):
        source = Mock(return_value={
            'userId': 'UID-17', 'status': 'active', 'super_admin': True})
        person = staff_user()
        actual = mask_unverified_staff(
            person, enabled=True, uid_loader=lambda _: 'UID-17',
            fetch_subject=source)
        self.assertIs(actual, person)
        self.assertTrue(actual.is_staff)
        self.assertEqual(actual.admin_role, 'default_admin')
        source.assert_called_once_with('UID-17')

    def test_revoked_uid_masks_cookie_or_api_token_staff_even_if_db_says_true(self):
        for category in ('Session', 'TokenV1', 'TokenV2'):
            person = staff_user()
            with self.subTest(category=category):
                actual = mask_unverified_staff(
                    person, enabled=True, uid_loader=lambda _: 'UID-17',
                    fetch_subject=lambda _: {
                        'userId': 'UID-17', 'status': 'active', 'super_admin': False})
                self.assertFalse(actual.is_staff)
                self.assertFalse(actual.is_superuser)
                self.assertEqual(actual.admin_role, '')
                self.assertTrue(actual.is_active)  # ordinary authorized files unchanged

    def test_directory_failure_rejects_privilege_without_denying_all_file_access(self):
        for source in (
            lambda uid: (_ for _ in ()).throw(RuntimeError('source unavailable')),
            lambda uid: {'userId': uid, 'status': 'active'},
            lambda uid: {'userId': uid, 'status': 'disabled', 'super_admin': False},
            lambda uid: {'userId': 'other-uid', 'status': 'active', 'super_admin': True},
            lambda uid: {'userId': uid, 'status': 'active', 'super_admin': 'true'},
        ):
            person = staff_user()
            with self.subTest(source=source):
                mask_unverified_staff(
                    person, enabled=True, uid_loader=lambda _: 'UID-17',
                    fetch_subject=source)
                self.assertFalse(person.is_staff)
                self.assertEqual(person.admin_role, '')
                self.assertTrue(person.is_active)

    def test_missing_unverifiable_uid_fails_closed(self):
        person = staff_user()
        mask_unverified_staff(
            person, enabled=True, uid_loader=lambda _: None,
            fetch_subject=lambda _: self.fail('must not fetch missing UID'))
        self.assertFalse(person.is_staff)

    def test_ce_standalone_and_nonstaff_never_depend_on_enterprise(self):
        native = staff_user()
        source = Mock(side_effect=AssertionError('must not fetch disabled feature'))
        mask_unverified_staff(native, enabled=False,
                              uid_loader=lambda _: self.fail('must not load UID'),
                              fetch_subject=source)
        self.assertTrue(native.is_staff)
        source.assert_not_called()

        person = staff_user()
        person.is_staff = False
        mask_unverified_staff(person, enabled=True,
                              uid_loader=lambda _: self.fail('must not load UID'),
                              fetch_subject=source)
        self.assertFalse(person.is_staff)
        source.assert_not_called()


if __name__ == '__main__':
    import unittest
    unittest.main()
