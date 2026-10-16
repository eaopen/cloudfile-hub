"""Exercise the real V2 discovery HTTP view without a CE service fixture."""
import json
import unittest

from django.conf import settings

if not settings.configured:
    settings.configure(DEFAULT_CHARSET='utf-8', SECRET_KEY='discovery-test-only')

from django.test import RequestFactory
from django.urls import resolve

from cloudfile_ext.v2.capabilities import capability_document


class CapabilitiesTest(unittest.TestCase):
    def test_discovery_resolves_and_does_not_require_admin_credentials(self):
        match = resolve('/capabilities/', urlconf='cloudfile_ext.v2.urls')
        response = match.func(RequestFactory().get('/capabilities/'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Cache-Control'], 'no-store')
        value = json.loads(response.content)
        self.assertEqual(value['product'], 'CloudFile')
        self.assertEqual(value['version'], '2.0.0-dev')
        self.assertEqual(value['contract_version'], '1.0')
        self.assertEqual(value, capability_document())

    def test_schema_or_helper_modules_never_advertise_unassembled_features(self):
        value = capability_document()
        for name in ('auth.oidc', 'directory.groups.manage', 'library.policy',
                     'directory.acl', 'directory.acl.manage', 'directory.acl.effective',
                     'identity.users.resolve', 'directory.shares'):
            self.assertEqual(value['capabilities'][name], {'enabled': False})
        self.assertTrue(all(item == {'enabled': False} for item in value['capabilities'].values()))

    def test_discovery_rejects_mutation(self):
        match = resolve('/capabilities/', urlconf='cloudfile_ext.v2.urls')
        self.assertEqual(match.func(RequestFactory().post('/capabilities/')).status_code, 405)
