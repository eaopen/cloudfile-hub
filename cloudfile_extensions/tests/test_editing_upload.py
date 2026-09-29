"""Transport regression for one real-publisher invocation and unknown outcome."""
from contextlib import contextmanager
import json
import tempfile
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from django.core.files.uploadedfile import SimpleUploadedFile
from django.middleware.csrf import _get_new_csrf_string
from django.test import RequestFactory

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.editing.service import EditingService
from cloudfile_extensions.editing.upload import EditingUploadView, EditingCheckinView
SESSION_REFERENCE_KEY = "cf_oidc_session_reference"


class Session(dict):
    session_key = "native-session-key"


class EditingUploadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from django.conf import settings
        if not settings.configured:
            settings.configure(SECRET_KEY="fixture-only", ALLOWED_HOSTS=["testserver"],
                DEFAULT_CHARSET="utf-8")
        import django
        django.setup()

    def setUp(self):
        self.request_factory = RequestFactory()
        self.intent_id = str(uuid4())
        self.reference = dict(repo_id="22222222-2222-4222-8222-222222222222",
                              path="/sample.docx", kind="file")
        self.payload = dict(repo_id=self.reference["repo_id"], path=self.reference["path"],
            guard_id="11111111-1111-4111-8111-111111111111", generation="1",
            credential_epoch="1", token="a" * 64, intent_id=self.intent_id,
            base_file_id="b" * 40, head_id="d" * 40, action="commit")
        self.service = object.__new__(EditingService)
        self.service.holder = "h" * 64
        self.service.resources = Mock()
        authority = self.service.resources.write_authority
        authority.actor = "employee"
        authority.preparation.state.provider = "provider"
        authority.preparation.contexts.current.return_value = {"context_epoch": 7}
        self.service.command = Mock(return_value={"receipt": {"intent_id": self.intent_id,
            "resource_uid": "33333333-3333-4333-8333-333333333333", "state": "prepared"}})

        @contextmanager
        def factory(request, request_id):
            yield self.service
        self.view = EditingUploadView.as_view(service_factory=factory)

    def request(self, content=b"new content"):
        csrf = _get_new_csrf_string()
        request = self.request_factory.post("/commit-file/",
            data={**self.payload, "file": SimpleUploadedFile("sample.docx", content)},
            secure=True, HTTP_COOKIE="csrftoken=" + csrf, HTTP_X_CSRFTOKEN=csrf,
            HTTP_ORIGIN="https://testserver", HTTP_IDEMPOTENCY_KEY="attempt-1")
        request.session = Session({SESSION_REFERENCE_KEY: {"scope_hash": "f" * 64}})
        return request

    @contextmanager
    def patched(self, directory, native_result):
        @contextmanager
        def login_scope():
            yield object()
        @contextmanager
        def guard(request):
            yield None
        with patch.dict("os.environ", {"SEAFILE_DATA_DIR": directory}), \
             patch("cloudfile_extensions.identity.read_ticket_http.native_download_actor",
                   return_value=Mock(user_id="employee", native_username="employee")), \
             patch("cloudfile_extensions.editing.upload.login_resources_scope", login_scope), \
             patch("cloudfile_extensions.identity.session_authority.OIDCSessionAuthority") as oidc, \
             patch("cloudfile_extensions.identity.ticket_transport._call", side_effect=native_result) as rpc:
            oidc.return_value.guard.side_effect = guard
            yield rpc

    def test_commit_receipt_is_read_after_native_ack(self):
        result = dict(intent_id=self.intent_id, state="published", result_file_id="c" * 40,
            content_digest=__import__("hashlib").sha256(b"new content").hexdigest())
        self.service.query = Mock(side_effect=[ContractError("NOT_FOUND", "Not found", 404), result])
        with tempfile.TemporaryDirectory() as directory:
            __import__("os").mkdir(directory + "/httptemp")
            with self.patched(directory, ["c" * 40]) as rpc:
                response = self.view(self.request())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.content)["intent"]["state"], "published")
        self.assertEqual(self.service.command.call_args.args[0], "prepare")
        self.assertEqual(rpc.call_args.args[0], "seafile_cloudfile_publish_edit")
        condition = json.loads(rpc.call_args.args[1][5])
        self.assertEqual(condition["path"], self.reference["path"])

    def test_unknown_native_result_uses_durable_receipt(self):
        result = dict(intent_id=self.intent_id, state="published", result_file_id="c" * 40)
        self.service.query = Mock(side_effect=[ContractError("NOT_FOUND", "Not found", 404), result])
        with tempfile.TemporaryDirectory() as directory:
            __import__("os").mkdir(directory + "/httptemp")
            with self.patched(directory, [TimeoutError("lost response")]):
                response = self.view(self.request())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.content)["intent"]["state"], "published")

    def test_stale_expected_head_reports_conflict_without_releasing_checkout(self):
        prepared = dict(intent_id=self.intent_id, state="prepared")
        self.service.query = Mock(side_effect=[ContractError("NOT_FOUND", "Not found", 404), prepared])
        with tempfile.TemporaryDirectory() as directory:
            __import__("os").mkdir(directory + "/httptemp")
            with self.patched(directory, [TimeoutError("native refusal"),
                                          {"head_cmmt_id": "e" * 40}]):
                response = self.view(self.request())
        self.assertEqual(response.status_code, 409)
        self.assertEqual(json.loads(response.content)["code"], "RESOURCE_VERSION_CONFLICT")

    def test_unchanged_checkin_uses_native_rpc_and_historical_receipt(self):
        result = dict(intent_id=self.intent_id, state="published", result_file_id="b" * 40)
        self.service.query = Mock(side_effect=[ContractError("NOT_FOUND", "Not found", 404), result])
        csrf = _get_new_csrf_string()
        request = self.request_factory.post("/checkin/",
            data=json.dumps({key: value for key, value in self.payload.items() if key != "action"}),
            content_type="application/json", secure=True,
            HTTP_COOKIE="csrftoken=" + csrf, HTTP_X_CSRFTOKEN=csrf,
            HTTP_ORIGIN="https://testserver", HTTP_IDEMPOTENCY_KEY="checkin-1")
        request.session = Session({SESSION_REFERENCE_KEY: {"scope_hash": "f" * 64}})
        with tempfile.TemporaryDirectory() as directory:
            with self.patched(directory, ["b" * 40]) as rpc:
                response = EditingCheckinView.as_view(service_factory=self.view.view_initkwargs["service_factory"])(request)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.service.command.call_args.args[0], "prepare")
        self.assertEqual(self.service.command.call_args.args[1]["action"], "checkin-unchanged")
        self.assertEqual(rpc.call_args.args[0], "seafile_cloudfile_checkin_edit")

    def test_checkin_response_loss_retries_original_intent_without_second_rpc(self):
        from cloudfile_extensions.editing.upload import EMPTY_CONTENT_DIGEST
        result = dict(intent_id=self.intent_id, resource_uid="33333333-3333-4333-8333-333333333333",
            guard_id=self.payload["guard_id"], generation="1", credential_epoch="1",
            expected_file_id="b" * 40, staged_file_id="b" * 40,
            content_digest=EMPTY_CONTENT_DIGEST, action="checkin-unchanged",
            state="published", result_file_id="b" * 40)
        self.service.query = Mock(return_value=result)
        # The durable Prepare retry receipt precedes native publication. It has
        # no result_file_id even though the historical intent is now published.
        self.service.command = Mock(return_value={"receipt": {
            "intent_id": self.intent_id, "state": "prepared"}})
        csrf = _get_new_csrf_string()
        request = self.request_factory.post("/checkin/",
            data=json.dumps({key: value for key, value in self.payload.items() if key != "action"}),
            content_type="application/json", secure=True,
            HTTP_COOKIE="csrftoken=" + csrf, HTTP_X_CSRFTOKEN=csrf,
            HTTP_ORIGIN="https://testserver", HTTP_IDEMPOTENCY_KEY="checkin-1")
        request.session = Session({SESSION_REFERENCE_KEY: {"scope_hash": "f" * 64}})
        with tempfile.TemporaryDirectory() as directory:
            with self.patched(directory, []) as rpc:
                response = EditingCheckinView.as_view(service_factory=self.view.view_initkwargs["service_factory"])(request)
        self.assertEqual(response.status_code, 200)
        rpc.assert_not_called()

    def test_source_workcopy_identity_is_bound_to_the_frozen_snapshot(self):
        self.payload['source_identity'] = 'workcopy:' + 'f' * 64
        result = dict(intent_id=self.intent_id, state='published', result_file_id='c' * 40)
        self.service.query = Mock(side_effect=[ContractError('NOT_FOUND','Not found',404),result])
        with tempfile.TemporaryDirectory() as directory:
            __import__('os').mkdir(directory + '/httptemp')
            with self.patched(directory,['c' * 40]):
                response=self.view(self.request())
        self.assertEqual(response.status_code,200)
        snapshot=self.service.command.call_args.args[1]['snapshot']
        self.assertEqual(snapshot,dict(id=self.intent_id,size=len(b'new content'),source=self.payload['source_identity']))
