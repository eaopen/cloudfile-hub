"""Runtime integration failures never become native membership readiness."""
from contextlib import contextmanager
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from django.test import override_settings

from cloudfile_ext.v2.etech_directory import Directory, prepare_user, prepare_group, ensure_subject
from cloudfile_ext.v2.errors import IdentityUnavailable


def subject(status='active'):
    return dict(userId='uid', status=status, attributes={'employee_no':'E001'},
                organizations=[dict(namespace='directory', external_id='o1')] if status=='active' else [],
                organization_ancestors=[], roles=[], etag='version', generated_at=datetime.now(timezone.utc).isoformat())


class DirectoryRuntimeTests(TestCase):
    @contextmanager
    def runtime(self):
        self.directory, self.identity, self.catalog, self.memberships = (Mock() for _ in range(4))
        self.directory.subject.return_value=subject()
        self.directory.entities.return_value={('org','directory','o1'):'Department'}
        self.identity.prepare.return_value='opaque@auth.local'
        self.catalog.ensure.return_value=42
        yield self.directory, self.identity, self.catalog, self.memberships

    def test_preparation_proves_directory_uid_and_preserves_native_name(self):
        with patch('cloudfile_ext.v2.etech_directory.runtime',self.runtime):
            self.assertEqual(prepare_user('uid'),'opaque@auth.local')
        self.directory.subject.assert_called_once_with('uid')
        self.identity.prepare.assert_called_once_with(uid='uid',login_name='E001')
        self.memberships.ensure.assert_not_called()

    def test_disabled_or_changed_uid_cannot_create_native_account(self):
        for value in (subject('disabled'),dict(subject(),userId='other')):
            @contextmanager
            def runtime():
                with self.runtime() as parts:
                    self.directory.subject.return_value=value
                    yield parts
            with patch('cloudfile_ext.v2.etech_directory.runtime',runtime):
                with self.assertRaises(IdentityUnavailable):prepare_user('uid')
            self.identity.prepare.assert_not_called()

    def test_group_mapping_uses_exact_type_namespace_and_external_id(self):
        with patch('cloudfile_ext.v2.etech_directory.runtime',self.runtime):
            self.assertEqual(prepare_group('o1'),42)
        self.catalog.ensure.assert_called_once_with('org','directory','o1','Department')
        with patch('cloudfile_ext.v2.etech_directory.runtime',self.runtime):
            with self.assertRaises(IdentityUnavailable):prepare_group('role:o1')
        self.catalog.ensure.assert_not_called()

    def test_default_projector_refreshes_only_current_uid_and_proves_entities(self):
        with patch('cloudfile_ext.v2.etech_directory.runtime',self.runtime):
            ensure_subject('uid','opaque@auth.local')
        self.memberships.ensure.assert_called_once_with('uid','opaque@auth.local')
        self.assertEqual(self.memberships.fetch('uid')['userId'],'uid')
        self.catalog.ensure.assert_called_once_with('org','directory','o1','Department')
        self.directory.entities.side_effect=IdentityUnavailable()
        with self.assertRaises(IdentityUnavailable):self.memberships.fetch('uid')

    def test_connection_requires_scoped_service_credential(self):
        with override_settings(CF_DIRECTORY_URL='https://directory.test/eap/cloudDrive/directory',
                               CF_DIRECTORY_SECRET='',CF_DIRECTORY_KEY_ID='key'):
            with self.assertRaises(IdentityUnavailable):Directory()

    def test_directory_request_is_short_lived_scoped_and_does_not_follow_redirect(self):
        import jwt
        secret='isolated-directory-test-secret-32-bytes'
        response=Mock()
        response.__enter__=Mock(return_value=response)
        response.__exit__=Mock(return_value=False)
        response.status_code=200
        response.iter_content.return_value=[b'{"groups":[]}']
        with override_settings(CF_DIRECTORY_URL='https://directory.test/eap/cloudDrive/directory',
                               CF_DIRECTORY_SECRET=secret,CF_DIRECTORY_KEY_ID='key'), \
                patch('cloudfile_ext.v2.etech_directory.requests.get',return_value=response) as get:
            self.assertEqual(Directory().get('/groups?view=entities'),{'groups':[]})
            kwargs=get.call_args.kwargs
            self.assertFalse(kwargs['allow_redirects'])
            token=kwargs['headers']['Authorization'].split()[1]
            claims=jwt.decode(token,secret,algorithms=['HS256'],audience='eap-directory',issuer='cloudfile-sso')
            self.assertEqual(claims['scope'],'directory.read')
            self.assertEqual(claims['sub'],'cloudfile')
            self.assertEqual(claims['exp']-claims['iat'],60)
            response.status_code=302
            with self.assertRaises(IdentityUnavailable):Directory().get('/groups?view=entities')
