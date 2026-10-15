"""The editing holder accepts either native session, like the shared lists.

Protocol selection is by the server session backend, never by a client hint.
A legacy OAuth session must be able to name an editing holder, and a session
the selected authority rejects must never become one.
"""
from contextlib import contextmanager
import sys
import types
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from django.conf import settings

from cloudfile_extensions.authorization.runtime import AuthenticatedPolicyActor
from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.editing.runtime import native_session_holder
from cloudfile_extensions.identity.browser_session import LEGACY_BACKEND
from cloudfile_extensions.identity.native_session import BACKEND

if not settings.configured:
    settings.configure(SECRET_KEY='fixture-only', ALLOWED_HOSTS=['testserver'])


class Session(dict):
    session_key = 'persisted-session'


class EditingHolderSessionTests(TestCase):
    def setUp(self):
        auth = types.ModuleType('seahub.auth')
        auth.SESSION_KEY, auth.BACKEND_SESSION_KEY = '_auth_user_id', '_auth_user_backend'
        modules = patch.dict(sys.modules, {'seahub.auth': auth})
        modules.start()
        self.addCleanup(modules.stop)
        self.request = SimpleNamespace(session=Session(
            _auth_user_id='native-user', _auth_user_backend=LEGACY_BACKEND))
        self.actor = AuthenticatedPolicyActor('business-uid', 'native-user')
        self.resources = Mock()
        self.resources.write_authority.actor = 'business-uid'
        self.resources.write_authority.state.username.return_value = 'native-user'

    @contextmanager
    def login_scope(self):
        self.login_resources = Mock()
        yield self.login_resources

    def holder(self, actor=None, check=None):
        authority = Mock()
        authority.check.side_effect = check
        with patch('cloudfile_extensions.authorization.gunicorn.login_resources_scope',
                   return_value=self.login_scope()), \
                patch('cloudfile_extensions.identity.browser_session.browser_session',
                      return_value=(actor or self.actor, authority)) as dispatch:
            holder = native_session_holder(self.request, self.resources)
        return holder, dispatch, authority

    def test_legacy_oauth_session_names_the_editing_holder(self):
        holder, dispatch, authority = self.holder()
        self.assertEqual(holder, 'persisted-session')
        self.assertEqual(dispatch.call_args.args, (self.request, self.login_resources))
        authority.check.assert_called_once_with(self.request)

    def test_oidc_session_keeps_the_same_holder_contract(self):
        self.request.session['_auth_user_backend'] = BACKEND
        holder, dispatch, _ = self.holder()
        self.assertEqual(holder, 'persisted-session')
        self.assertEqual(dispatch.call_args.args, (self.request, self.login_resources))

    def test_rejected_session_never_becomes_a_holder(self):
        with self.assertRaises(ContractError) as raised:
            self.holder(check=ContractError('AUTHENTICATION_REQUIRED', 'Ended', 401))
        self.assertEqual(raised.exception.code, 'AUTHENTICATION_REQUIRED')

    def test_changed_native_identity_never_becomes_a_holder(self):
        with self.assertRaises(ContractError) as raised:
            self.holder(actor=AuthenticatedPolicyActor('business-uid', 'other-user'))
        self.assertEqual(raised.exception.code, 'AUTHENTICATION_REQUIRED')
