"""Shared and racing mailboxes cannot collapse distinct OAuth identities."""

from contextlib import contextmanager
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import patch

from cloudfile_ext.sso.oauth_profile import update_optional_contact_email


class IntegrityError(Exception):
    pass


@contextmanager
def atomic(**kwargs):
    yield


class Profiles:
    def __init__(self):
        self.rows = {}

    def filter(self, **kwargs):
        value = kwargs['contact_email__iexact']
        return SimpleNamespace(exclude=lambda **excluded: SimpleNamespace(
            exists=lambda: any(user != excluded['user'] and email.lower() == value
                               for user, email in self.rows.items())))


class Profile:
    objects = Profiles()

    def __init__(self, user, email=None):
        self.user = user
        self.contact_email = email
        self.is_manually_set_contact_email = False
        self._state = SimpleNamespace(db='default')
        self.login_id = user
        self.fail = None

    def save(self):
        if self.fail:
            self.fail()
            raise IntegrityError('fixture unique constraint')
        self.objects.rows[self.user] = self.contact_email


class OAuthProfileTest(unittest.TestCase):
    def setUp(self):
        Profile.objects = Profiles()
        db = SimpleNamespace(IntegrityError=IntegrityError,
                             transaction=SimpleNamespace(atomic=atomic))
        self.stub = patch.dict(sys.modules, {'django.db': db})
        self.stub.start()
        self.addCleanup(self.stub.stop)

    def test_duplicate_email_keeps_two_employee_profiles(self):
        first = Profile('employee-001')
        second = Profile('employee-002')
        self.assertTrue(update_optional_contact_email(first, 'SHARED@example.com'))
        self.assertFalse(update_optional_contact_email(second, 'shared@example.com'))
        self.assertIsNone(second.contact_email)
        self.assertEqual(second.login_id, 'employee-002')
        self.assertEqual(Profile.objects.rows, {'employee-001': 'shared@example.com'})

    def test_empty_email_does_not_prevent_employee_login(self):
        profile = Profile('employee-001')
        self.assertFalse(update_optional_contact_email(profile, ''))
        self.assertEqual(profile.login_id, 'employee-001')

    def test_manual_contact_address_is_preserved(self):
        profile = Profile('employee-001', 'manual@example.com')
        profile.is_manually_set_contact_email = True
        self.assertFalse(update_optional_contact_email(profile, 'new@example.com'))
        self.assertEqual(profile.contact_email, 'manual@example.com')

    def test_concurrent_duplicate_restores_original_contact_address(self):
        profile = Profile('employee-002', 'original@example.com')
        profile.fail = lambda: Profile.objects.rows.update({'employee-001': 'shared@example.com'})
        self.assertFalse(update_optional_contact_email(profile, 'shared@example.com'))
        self.assertEqual(profile.contact_email, 'original@example.com')

    def test_unrelated_integrity_error_remains_an_error(self):
        profile = Profile('employee-001', 'original@example.com')
        profile.fail = lambda: None
        with self.assertRaises(IntegrityError):
            update_optional_contact_email(profile, 'new@example.com')
        self.assertEqual(profile.contact_email, 'original@example.com')


if __name__ == '__main__':
    unittest.main()
