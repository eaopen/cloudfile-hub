"""The CloudFile subject gate: no ready subject, no CloudFile answer.

Self-contained: it configures minimal Django settings so the DRF permission
class can be exercised without the native Seahub stack. The login hook and the
native UID anchor live in ``test_etech_http.py``, which needs that stack.
"""
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import django
from django.conf import settings

if not settings.configured:
    settings.configure(DEBUG=False, DATABASES={}, INSTALLED_APPS=[], USE_TZ=True)
    django.setup()

from rest_framework.exceptions import APIException

from cloudfile_ext.v2.errors import IdentityUnavailable, SubjectNotBound
from cloudfile_ext.v2.permissions import SubjectReady


def request(authenticated=True):
    return SimpleNamespace(user=SimpleNamespace(username='user@auth.local', is_authenticated=authenticated))


class SubjectGateTest(unittest.TestCase):
    def test_inert_without_a_configured_directory(self):
        # No CF_DIRECTORY_URL/CF_DIRECTORY_TOKEN: the native path is unchanged.
        self.assertTrue(SubjectReady().has_permission(request(), None))

    def test_anonymous_requests_are_left_to_native_authentication(self):
        self.assertFalse(SubjectReady().has_permission(request(authenticated=False), None))

    def test_ready_subject_passes_for_the_authenticated_native_user(self):
        with patch('cloudfile_ext.v2.permissions.require_ready', return_value=True) as gate:
            self.assertTrue(SubjectReady().has_permission(request(), None))
        gate.assert_called_once_with('user@auth.local')

    def test_missing_binding_is_forbidden_and_failed_refresh_is_unavailable(self):
        for error, expected_status, expected_code in (
                (SubjectNotBound('no uid'), 403, 'CF_SUBJECT_MISSING'),
                (IdentityUnavailable('directory down'), 503, 'CF_SUBJECT_UNAVAILABLE')):
            with self.subTest(error=type(error).__name__), \
                    patch('cloudfile_ext.v2.permissions.require_ready', side_effect=error):
                with self.assertRaises(APIException) as raised:
                    SubjectReady().has_permission(request(), None)
            self.assertEqual(raised.exception.status_code, expected_status)
            self.assertEqual(raised.exception.default_code, expected_code)


if __name__ == '__main__':
    unittest.main()
