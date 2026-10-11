"""Exercise the real encrypted grant and HTTP byte boundary; RPC is a fixture."""
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from django.test import RequestFactory

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.local_edit.agent_runtime import AgentClaimRuntime
from cloudfile_extensions.local_edit.upload_grant import seal, unseal, UPLOAD_PATH
from cloudfile_extensions.local_edit.upload_http import AgentUploadView, stage


class UploadGrantTests(unittest.TestCase):
    def test_expiry_tampering_wrong_key_and_encryption(self):
        secret = b'a' * 32
        data = dict(token='private-checkout-token', intent='original')
        ticket = seal(secret, data, now=100)
        self.assertNotIn(data['token'], ticket)
        self.assertEqual(unseal(secret, ticket, now=159), data)
        for key, token, now in ((secret, ticket, 160), (secret, ticket, 99),
                (b'b' * 32, ticket, 100), (secret, ticket + 'a', 100),
                (secret, ticket + '=', 100), (secret, ticket.replace('v1.', 'v2.'), 100)):
            with self.subTest(now=now, token=token[:10]), self.assertRaises(ContractError):
                unseal(key, token, now=now)

    def test_bounded_stream_empty_and_mismatched_content(self):
        for content in (b'', b'captured bytes'):
            with tempfile.TemporaryFile() as output:
                stage(io.BytesIO(content), output, size=len(content), digest=hashlib.sha256(content).hexdigest())
                output.seek(0)
                self.assertEqual(output.read(), content)
        for content, size, digest in ((b'x', 2, hashlib.sha256(b'x').hexdigest()),
                (b'extra', 2, hashlib.sha256(b'ex').hexdigest()), (b'x', 1, '0' * 64)):
            with tempfile.TemporaryFile() as output, self.assertRaises(ContractError):
                stage(io.BytesIO(content), output, size=size, digest=digest)


class DeviceUploadHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from django.conf import settings
        if not settings.configured:
            settings.configure(SECRET_KEY='fixture', ALLOWED_HOSTS=['testserver'], DEFAULT_CHARSET='utf-8')
        import django
        django.setup()

    def setUp(self):
        self.content = b'original snapshot'
        self.intent = '33333333-3333-4333-8333-333333333333'
        self.runtime = object.__new__(AgentClaimRuntime)
        self.runtime.pid = os.getpid()
        self.runtime.secret = b'a' * 32
        self.runtime.instance = 'https://testserver'
        self.runtime.agent2_exclusive_enabled = True
        self.grant = dict(instance=self.runtime.instance, native_user='native-user',
            snapshot_size=len(self.content), content_digest=hashlib.sha256(self.content).hexdigest(), action='commit',
            condition=dict(path='/file.txt', editing=dict(repo_id='repo', intent_id=self.intent,
                base_file_id='b' * 40), local_commit=dict(session_id='session', device_id='device')))
        self.published = dict(intent_id=self.intent, state='published', result_file_id='c' * 40,
            content_digest=self.grant['content_digest'], expected_file_id='b' * 40, action='commit', checked_in=False)
        self.runtime.upload_receipt = Mock(side_effect=[dict(intent_id=self.intent, state='prepared'), self.published])
        self.view = AgentUploadView.as_view(runtime=self.runtime)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        (Path(self.temp.name) / 'httptemp').mkdir()
        self.env = patch.dict(os.environ, SEAFILE_DATA_DIR=self.temp.name)
        self.env.start(); self.addCleanup(self.env.stop)

    def request(self, content=None, **headers):
        request = RequestFactory().post(UPLOAD_PATH, data=self.content if content is None else content,
            content_type='application/octet-stream', secure=True,
            HTTP_AUTHORIZATION='Bearer ' + seal(self.runtime.secret, self.grant),
            HTTP_IDEMPOTENCY_KEY=self.intent, **headers)
        if 'HTTP_COOKIE' not in headers:
            request.META.pop('HTTP_COOKIE', None)
        return request

    def rpc(self, name, args, deadline):
        if name == 'seafile_get_repo':
            return dict(head_cmmt_id='d' * 40)
        self.assertEqual(name, 'seafile_cloudfile_publish_edit')
        self.assertEqual(Path(args[1]).read_bytes(), self.content)
        self.assertEqual(args[2:5], ('/', 'file.txt', 'native-user'))
        condition = json.loads(args[5])
        self.assertIn('local_commit', condition)
        self.assertNotIn('oidc_session', condition)
        raise TimeoutError('published but response lost')

    def test_lost_native_response_returns_durable_receipt_and_cleans_stage(self):
        with patch('cloudfile_extensions.identity.ticket_transport._call', side_effect=self.rpc) as rpc:
            response = self.view(self.request())
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(json.loads(response.content)['intent'], self.published)
        self.assertEqual(rpc.call_count, 2)
        self.assertEqual(list((Path(self.temp.name) / 'httptemp').iterdir()), [])

    def test_published_replay_does_not_publish_again(self):
        self.runtime.upload_receipt.side_effect = None
        self.runtime.upload_receipt.return_value = self.published
        with patch('cloudfile_extensions.identity.ticket_transport._call') as rpc:
            self.assertEqual(self.view(self.request()).status_code, 200)
        rpc.assert_not_called()

    def test_unconfirmed_never_reports_saved(self):
        self.runtime.upload_receipt.side_effect = None
        self.runtime.upload_receipt.return_value = dict(intent_id=self.intent, state='prepared')
        with patch('cloudfile_extensions.identity.ticket_transport._call', side_effect=self.rpc):
            response = self.view(self.request())
        self.assertEqual(response.status_code, 503)
        self.assertEqual(json.loads(response.content)['code'], 'PUBLICATION_UNCONFIRMED')

    def test_bad_bytes_headers_expired_or_wrong_intent_never_call_native(self):
        requests = [self.request(b'x' * len(self.content)), self.request(HTTP_COOKIE=''),
            self.request(HTTP_CONTENT_ENCODING='gzip'), self.request(HTTP_TRANSFER_ENCODING='chunked')]
        request = self.request(); request.META['HTTP_IDEMPOTENCY_KEY'] = 'another'; requests.append(request)
        request = self.request(); request.META['HTTP_AUTHORIZATION'] = 'Bearer ' + seal(self.runtime.secret, self.grant, now=1); requests.append(request)
        request = self.request(); request.META['CONTENT_LENGTH'] = '999999999'; requests.append(request)
        with patch('cloudfile_extensions.identity.ticket_transport._call') as rpc:
            for request in requests:
                with self.subTest(request=request.META):
                    self.assertIn(self.view(request).status_code, (400, 401))
        rpc.assert_not_called()
        self.runtime.upload_receipt.assert_not_called()
        self.assertEqual(list((Path(self.temp.name) / 'httptemp').iterdir()), [])

    def test_default_disabled_and_origin_mismatch(self):
        self.runtime.agent2_exclusive_enabled = False
        self.assertEqual(self.view(self.request()).status_code, 503)
        self.runtime.agent2_exclusive_enabled = True
        self.grant['instance'] = 'https://other.example'
        self.assertEqual(self.view(self.request()).status_code, 401)
