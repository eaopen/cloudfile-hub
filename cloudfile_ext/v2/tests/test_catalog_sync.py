"""V2 entity catalog: no full-member sync, stable IDs and short-lived service auth."""
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

import jwt

from cloudfile_ext.v2.catalog_sync import reconcile, validate_entities
from cloudfile_ext.v2.directory_client import DirectoryClient, configuration
from cloudfile_ext.v2.errors import IdentityUnavailable


def catalog(rows):
    return dict(view='entities', contract_version='2.0', revision='sha256:' + 'a'*64,
                generated_at=datetime.now(timezone.utc).isoformat(), groups=rows)


def entity(kind, eid, *, parent=None, name='Entity'):
    return dict(subject_type=kind, namespace='directory' if kind == 'org' else 'role',
                external_id=eid, name=name, parent_external_id=parent)


class CatalogTests(TestCase):
    def test_catalog_contains_entities_only_and_validates_parent_ids(self):
        rows = [entity('org','10'), entity('org','11',parent='10'),
                entity('role','20')]
        self.assertEqual(len(validate_entities(catalog(rows))), 3)
        for invalid in ([entity('org','11',parent='99')], [entity('org','11',parent='11')],
                        [entity('org','10'), entity('org','10')],
                        [dict(entity('role','20'), member_user_ids=['uid'])]):
            with self.subTest(rows=invalid), self.assertRaises(IdentityUnavailable):
                validate_entities(catalog(invalid))

    def test_reconcile_uses_native_mappings_and_never_writes_members(self):
        rows = catalog([entity('org','10',name='Operations'), entity('role','20',name='Reviewer')])
        groups = {1:SimpleNamespace(group_name='Operations'), 2:SimpleNamespace(group_name='Old')}
        catalog_adapter = Mock()
        catalog_adapter.ensure.side_effect = [1, 2]
        def rename(group, name):
            groups[group] = SimpleNamespace(group_name=name)
        result = reconcile(rows, catalog=catalog_adapter, native_lookup=groups.get, rename=rename)
        self.assertEqual((result['entities'],result['renamed'],result['membership_writes']), (2,1,0))
        self.assertEqual(catalog_adapter.ensure.call_count, 2)

    def test_empty_or_malformed_response_cannot_delete_native_mapping(self):
        adapter = Mock()
        with self.assertRaises(IdentityUnavailable):
            reconcile(catalog([]),catalog=adapter,native_lookup=Mock(),rename=Mock())
        adapter.ensure.assert_not_called()


class DirectoryClientTests(TestCase):
    def config(self):
        settings = SimpleNamespace(
            CF_DIRECTORY_URL='https://etech.example.test/eap/cloudDrive/directory',
            CF_DIRECTORY_AUTH_KEY_ID='kid-1',
            CF_DIRECTORY_AUTH_SECRET='x'*40)
        return configuration(settings)

    def test_machine_jwt_has_short_lived_scope_and_kid(self):
        conf = self.config()
        c = DirectoryClient(conf, clock=lambda: 1800000000)
        token = c._token()
        self.assertEqual(jwt.get_unverified_header(token)['kid'], 'kid-1')
        claims = jwt.decode(token, conf['secret'], algorithms=['HS256'],
                            audience='eap-directory', issuer='cloudfile-sso',
                            options={'verify_exp':False, 'verify_iat':False})
        self.assertEqual((claims['sub'],claims['scope']), ('cloudfile','directory.read'))
        self.assertEqual(claims['exp']-claims['iat'], 60)

    def test_http_requires_explicit_opt_in_and_rejects_missing_secret(self):
        with self.assertRaises(IdentityUnavailable):
            configuration(SimpleNamespace(CF_DIRECTORY_URL='http://etech.example.test/directory',
                     CF_DIRECTORY_AUTH_KEY_ID='kid-1', CF_DIRECTORY_AUTH_SECRET='x'*40))
        with self.assertRaises(IdentityUnavailable):
            configuration(SimpleNamespace(CF_DIRECTORY_URL='https://etech.example.test/directory',
                     CF_DIRECTORY_AUTH_KEY_ID='kid-1', CF_DIRECTORY_AUTH_SECRET='short'))

    def test_invalid_redirect_never_supplies_entities(self):
        conf=self.config()
        opener=Mock()
        opener.open.side_effect=OSError('redirect')
        with self.assertRaises(IdentityUnavailable):
            DirectoryClient(conf,opener=opener).entities()
        req=opener.open.call_args.args[0]
        self.assertIn('view=entities', req.full_url)
        self.assertTrue(req.get_header('Authorization').startswith('Bearer '))


class CatalogHTTPTests(TestCase):
    def test_only_native_system_admin_may_trigger_catalog(self):
        from rest_framework.test import APIRequestFactory, force_authenticate
        from cloudfile_ext.v2.http import CatalogSync
        req=APIRequestFactory().post('/api/v2.1/admin/cloudfile/directory/entities/sync/', {},format='json')
        staff=SimpleNamespace(is_staff=True,is_authenticated=True,username='admin@auth.local',
                              admin_permissions=SimpleNamespace(can_manage_group=lambda:True))
        force_authenticate(req,staff)
        with patch('cloudfile_ext.v2.catalog_sync.run',
                   return_value=dict(status='OK',entities=3,membership_writes=0)) as run:
            response=CatalogSync.as_view()(req)
            self.assertEqual(response.status_code,200)
            run.assert_called_once()
        req=APIRequestFactory().post('/api/v2.1/admin/cloudfile/directory/entities/sync/', {},format='json')
        force_authenticate(req,SimpleNamespace(is_staff=False,is_authenticated=True,username='user@auth.local'))
        self.assertEqual(CatalogSync.as_view()(req).status_code,403)
