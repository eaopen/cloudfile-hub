"""Machine credential freshness and the A/B native UID boundary."""
import base64
import hashlib
import hmac
import json
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from cloudfile_ext.v2.directory import DirectoryMachineToken, DirectorySubjectClient
from cloudfile_ext.v2 import runtime
from cloudfile_ext.v2.errors import IdentityUnavailable, SubjectNotBound
from cloudfile_ext.v2.tests.test_directory import FakeOpener, FakeResponse


class MachineTokenTest(unittest.TestCase):
    def issuer(self):
        return DirectoryMachineToken('test-only-key-' + 'x' * 32, 'key-1', 'eap', 'directory', 'cloudfile')

    def test_each_fetch_issues_fresh_scoped_short_jwt_with_valid_signature(self):
        opener = FakeOpener(FakeResponse(200, b'{}'))
        client = DirectorySubjectClient('https://directory.test', self.issuer(), opener=opener)
        claims = []
        for now in (1000, 1400):
            with patch('cloudfile_ext.v2.directory.time.time', return_value=now):
                client.fetch('uid')
            token = opener.calls[-1][0].get_header('Authorization').removeprefix('Bearer ')
            a, b, c = token.split('.')
            decode = lambda value: base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
            self.assertEqual(json.loads(decode(a)), {'alg': 'HS256', 'typ': 'JWT', 'kid': 'key-1'})
            value = json.loads(decode(b))
            claims.append(value)
            self.assertEqual((value['iss'], value['aud'], value['sub'], value['scope']),
                             ('eap', 'directory', 'cloudfile', 'directory.read'))
            self.assertEqual((value['iat'], value['exp']), (now, now + 60))
            self.assertEqual(decode(c), hmac.new(self.issuer().secret, (a + '.' + b).encode(), hashlib.sha256).digest())
        self.assertNotEqual(claims[0]['jti'], claims[1]['jti'])

    def test_static_token_and_short_key_are_rejected(self):
        with self.assertRaises(IdentityUnavailable):
            DirectorySubjectClient('https://directory.test', 'static')
        with self.assertRaises(IdentityUnavailable):
            DirectoryMachineToken('short', 'kid', 'issuer', 'aud', 'service')

    def test_acl_adapter_requires_enabled_runtime_matching_provider_and_uid(self):
        subject = Mock(config={'provider': 'etech'})
        with patch.object(runtime, '_settings', return_value=SimpleNamespace(CF_ACL_PROVIDER='etech')), \
                patch.object(runtime, '_runtime_for', return_value=subject), \
                patch.object(runtime, 'bound_uid', return_value='UID'):
            self.assertTrue(runtime.ensure_acl_subject('UID', 'native'))
            subject.require_ready.assert_called_once_with('native', 'UID')
            with self.assertRaises(SubjectNotBound):
                runtime.ensure_acl_subject('uid', 'native')
        for subject in (None, Mock(config={'provider': 'other'})):
            with patch.object(runtime, '_settings', return_value=SimpleNamespace(CF_ACL_PROVIDER='etech')), \
                    patch.object(runtime, '_runtime_for', return_value=subject), self.assertRaises(IdentityUnavailable):
                runtime.ensure_acl_subject('UID', 'native')
