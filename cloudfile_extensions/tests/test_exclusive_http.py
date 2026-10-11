"""OIDC adapter orchestration fixtures; native/SQL acceptance runs separately."""
import json
from contextlib import contextmanager
import unittest
from unittest.mock import Mock, patch
from django.conf import settings
if not settings.configured:
    settings.configure(SECRET_KEY='exclusive-http-test', DEFAULT_CHARSET='utf-8', ALLOWED_HOSTS=['testserver'], INSTALLED_APPS=[])
import django
django.setup()
from django.test import RequestFactory
from cloudfile_extensions.editing.service import EditingService
from cloudfile_extensions.local_edit.session_service import LocalSessionService
from cloudfile_extensions.local_edit.exclusive_http import ExclusiveStartView, ExclusiveAbandonView

class ExclusiveHTTPTests(unittest.TestCase):
    def setUp(self):
        self.body=dict(reference=dict(repo_id='11111111-1111-4111-8111-111111111111',path='/drawing.dwg',kind='file'),
            device_id='22222222-2222-4222-8222-222222222222',base_file_id='a'*40)
        self.local=Mock(spec=LocalSessionService)
        self.local.agent2_exclusive_enabled=True
        self.local.owner=Mock()
        self.local.owner.status.return_value={'state':'active'}
        self.edit=Mock(spec=EditingService)
        self.edit.resources=Mock()
        self.edit.resources.store.secret=b's'*32
        authority=self.edit.resources.write_authority
        authority.state.provider='fixture';authority.actor='employee'
        self.edit.holder='oidc-session'
        self.checkout=dict(mode='checkout',guard_id='33333333-3333-4333-8333-333333333333',generation='1',credential_epoch='1',base_file_id='a'*40)
        self.edit.command.return_value={'receipt':self.checkout}
        self.local.create.return_value={'session_id':'44444444-4444-4444-8444-444444444444','state':'created','open_uri':'fixture'}

    def request(self, body=None, key='original-checkout-request'):
        return RequestFactory().post('/start-exclusive/',data=json.dumps(body or self.body),
            content_type='application/json',secure=True,HTTP_IDEMPOTENCY_KEY=key)

    def dispatch(self, request, view=ExclusiveStartView):
        @contextmanager
        def local(*args): yield self.local
        @contextmanager
        def editing(*args): yield self.edit
        with patch('cloudfile_extensions.authorization.gunicorn.local_session_service',side_effect=local), \
             patch('cloudfile_extensions.authorization.gunicorn.editing_service',side_effect=editing), \
             patch('django.middleware.csrf.CsrfViewMiddleware.process_view',return_value=None):
            return view.as_view()(request)

    def test_gate_and_revoked_device_fail_before_checkout(self):
        self.local.agent2_exclusive_enabled=False
        self.assertEqual(self.dispatch(self.request()).status_code,503)
        self.local.agent2_exclusive_enabled=True
        self.local.owner.status.return_value={'state':'revoked'}
        self.assertEqual(self.dispatch(self.request()).status_code,403)
        self.edit.command.assert_not_called()

    def test_session_failure_exposes_only_recovery_metadata_and_reuses_proof(self):
        self.local.create.side_effect=[RuntimeError('lost session reply'),self.local.create.return_value]
        first=self.dispatch(self.request())
        self.assertEqual(first.status_code,503)
        result=json.loads(first.content)
        self.assertEqual(result['checkout']['guard_id'],self.checkout['guard_id'])
        self.assertTrue(result['retry_original_request'])
        token=self.edit.command.call_args.args[1]['token']
        self.assertNotIn(token,first.content.decode())
        second=self.dispatch(self.request())
        self.assertEqual(second.status_code,201)
        self.assertEqual(self.edit.command.call_args.args[1]['token'],token)
        self.assertNotIn(token,second.content.decode())
        self.assertEqual(second['Referrer-Policy'],'no-referrer')

    def test_explicit_abandon_uses_original_secret_and_stable_command_identity(self):
        self.dispatch(self.request())
        token=self.edit.command.call_args.args[1]['token']
        self.edit.command.return_value={'receipt':{'guard_id':None}}
        body={**self.body,**{k:self.checkout[k] for k in ('guard_id','generation','credential_epoch')}}
        self.local.owner.status.return_value={'state':'revoked'}
        first=self.dispatch(self.request(body),ExclusiveAbandonView)
        self.assertEqual(first.status_code,200)
        original=self.edit.command.call_args
        self.assertEqual(original.args[0],'abandon')
        self.assertEqual(original.args[1]['token'],token)
        self.dispatch(self.request(body),ExclusiveAbandonView)
        self.assertEqual(original,self.edit.command.call_args)

    def test_csrf_and_machine_bearer_are_rejected(self):
        self.assertEqual(ExclusiveStartView.as_view()(self.request()).status_code,403)
        request=self.request();request.META['HTTP_AUTHORIZATION']='Bearer caller'
        self.assertEqual(self.dispatch(request).status_code,400)
        self.edit.command.assert_not_called()

if __name__=='__main__': unittest.main()
