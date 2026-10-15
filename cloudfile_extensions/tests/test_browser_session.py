"""Protocol selection and persisted legacy-session revocation boundaries."""
from contextlib import nullcontext
import sys
import types
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, MagicMock, patch

from django.conf import settings
from django.test import override_settings

from cloudfile_extensions.authorization.runtime import AuthenticatedPolicyActor
from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.identity.browser_session import (
    LEGACY_BACKEND, LegacyBrowserSessionAuthority, browser_session, legacy_browser_actor,
)
from cloudfile_extensions.identity.native_session import BACKEND
from cloudfile_extensions.identity.resources import LoginResources

if not settings.configured:
    settings.configure(SECRET_KEY='fixture-only', ALLOWED_HOSTS=['testserver'])


class Session(dict):
    session_key = 'persisted-session'


class BrowserSessionTests(TestCase):
    def setUp(self):
        auth = types.ModuleType('seahub.auth')
        auth.SESSION_KEY, auth.BACKEND_SESSION_KEY = '_auth_user_id', '_auth_user_backend'
        self.modules = patch.dict(sys.modules, {'seahub.auth': auth})
        self.modules.start()
        index = patch("cloudfile_extensions.identity.browser_session.OIDCSessionIndex")
        index.start()
        self.addCleanup(index.stop)
        self.addCleanup(self.modules.stop)
        self.request = SimpleNamespace(session=Session(
            _auth_user_id='native-user', _auth_user_backend=LEGACY_BACKEND))
        self.actor = AuthenticatedPolicyActor('business-uid', 'native-user')
        self.resources = Mock(spec=LoginResources)
        self.resources.oidc = SimpleNamespace(issuer='https://idp.example/', client_id='files')
        self.resources.resources = Mock(identity_schema='seahub_db')
        self.connection = MagicMock()
        self.cursor = self.connection.cursor.return_value.__enter__.return_value
        self.rows = [('signed-session',)]
        self.cursor.fetchall.side_effect = lambda: (("InnoDB",),) if (
            'SELECT ENGINE' in self.cursor.execute.call_args.args[0]) else self.rows
        self.resources.resources.connection.return_value = nullcontext(self.connection)
        self.native = Mock(table='`seahub_db`.`django_session`')
        self.native.decoder.decode.return_value = dict(self.request.session)

    def guard(self):
        return LegacyBrowserSessionAuthority(self.resources).guard(self.request)

    def test_legacy_requires_enabled_configured_oauth_backend(self):
        for enabled, backends in [(False, (LEGACY_BACKEND,)), (True, (BACKEND,))]:
            with override_settings(ENABLE_OAUTH=enabled, AUTHENTICATION_BACKENDS=backends), \
                    patch('cloudfile_extensions.identity.browser_session._native_actor') as actor:
                with self.assertRaises(ContractError):
                    legacy_browser_actor(self.request)
                actor.assert_not_called()

    def test_oidc_keeps_its_original_authority(self):
        self.request.session['_auth_user_backend'] = BACKEND
        with patch('cloudfile_extensions.identity.browser_session.native_download_actor', return_value=self.actor), \
                patch('cloudfile_extensions.identity.browser_session.OIDCSessionAuthority') as oidc:
            actor, authority = browser_session(self.request, self.resources)
            self.assertEqual(actor, self.actor)
            self.assertIs(authority, oidc.return_value)

    def test_persisted_legacy_session_checked_before_and_after_release(self):
        with patch('cloudfile_extensions.identity.browser_session.legacy_browser_actor', return_value=self.actor), \
                patch('cloudfile_extensions.identity.browser_session.NativeDBSessionDelete', return_value=self.native):
            with self.guard():
                self.assertEqual(self.native.decoder.decode.call_count, 1)
        self.assertEqual(self.native.decoder.decode.call_count, 2)
        self.connection.commit.assert_called_once()
        self.connection.rollback.assert_called_once()

    def test_expired_deleted_or_replaced_sessions_fail_before_release(self):
        for data in (None, {}, {'_auth_user_id': 'other', '_auth_user_backend': LEGACY_BACKEND},
                     {'_auth_user_id': 'native-user', '_auth_user_backend': BACKEND}):
            with self.subTest(data=data):
                self.rows = [] if data is None else [('signed',)]
                self.native.decoder.decode.return_value = data
                with patch('cloudfile_extensions.identity.browser_session.legacy_browser_actor', return_value=self.actor), \
                        patch('cloudfile_extensions.identity.browser_session.NativeDBSessionDelete', return_value=self.native):
                    with self.assertRaises(ContractError):
                        with self.guard():
                            self.fail('invalid session released protected response')
        self.connection.commit.assert_not_called()

    def test_rotated_session_and_changed_account_fail_at_release(self):
        for change in ('session', 'account'):
            self.request.session.session_key = 'persisted-session'
            self.connection.reset_mock()
            with patch('cloudfile_extensions.identity.browser_session.legacy_browser_actor', return_value=self.actor) as actor, \
                    patch('cloudfile_extensions.identity.browser_session.NativeDBSessionDelete', return_value=self.native):
                with self.assertRaises(ContractError):
                    with self.guard():
                        if change == 'session':
                            self.request.session.session_key = 'rotated'
                        else:
                            actor.return_value = AuthenticatedPolicyActor('changed-uid', 'native-user')
            self.connection.commit.assert_not_called()
