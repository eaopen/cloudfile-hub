"""CDC HTTP adapter contract: real RequestFactory, trusted runtime fixture.

Native Branch/storage integration is separately exercised by native_cdc_editing_e2e.
"""
import hashlib
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from django.conf import settings
if not settings.configured:
    settings.configure(SECRET_KEY="isolated-cdc-contract", DEFAULT_CHARSET="utf-8")
from django.test import RequestFactory, override_settings

from cloudfile_extensions.local_edit.agent_runtime import AgentClaimRuntime
from cloudfile_extensions.local_edit.block_http import AgentBlockView


class StubDevice(AgentClaimRuntime):
    def __init__(self, grant):
        self.grant = grant
        self.receipt = dict(state="prepared")

    def upload_grant(self, ticket, request_id):
        if ticket != "device-only-token":
            raise ValueError("not a current device grant")
        return self.grant

    def upload_receipt(self, grant, request_id):
        return self.receipt


class DeviceBlockHTTPTests(unittest.TestCase):
    def setUp(self):
        self.payload = b"CloudFile CDC stage: only signed bytes"
        self.block_id = hashlib.sha1(self.payload).hexdigest()
        self.intent = "11111111-1111-4111-8111-111111111111"
        self.grant = dict(
            snapshot_size=len(self.payload),
            content_digest=hashlib.sha256(self.payload).hexdigest(),
            native_user="editor@example.test",
            action="commit",
            condition=dict(path="/file.txt",
                editing=dict(repo_id="22222222-2222-4222-8222-222222222222",
                             base_file_id="a"*40, intent_id=self.intent),
                local_commit=dict(device_id="33333333-3333-4333-8333-333333333333",
                                  session_id="44444444-4444-4444-8444-444444444444")))
        self.runtime=StubDevice(self.grant)
        self.factory=RequestFactory()

    def request(self, name, data, ctype="application/json", **headers):
        request = self.factory.post("/cdc/"+name, data=data, content_type=ctype,
            secure=True, HTTP_AUTHORIZATION="Bearer device-only-token",
            HTTP_IDEMPOTENCY_KEY=self.intent, **headers)
        # Django RequestFactory inserts an empty Cookie header by default;
        # the real Go device client deliberately sends none.
        if "HTTP_COOKIE" not in headers:
            request.META.pop("HTTP_COOKIE", None)
        return request

    @override_settings(CLOUDFILE_AGENT2_CDC_ENABLED=True)
    def test_plan_exposes_only_missing_ids_and_own_intent(self):
        plan=dict(file_id="f"*40, size=len(self.payload),
                  sha256=self.grant["content_digest"],
                  blocks=[dict(id=self.block_id,size=len(self.payload))])
        with patch("cloudfile_extensions.local_edit.block_http._native_repo",return_value="a"*40), (
             patch("cloudfile_extensions.local_edit.block_http._read_blocks",
                   return_value=(plan,[self.block_id],{self.block_id:len(self.payload)}))), (
             patch("cloudfile_extensions.local_edit.block_http._call",
                   return_value=json.dumps([self.block_id]))):
            response=AgentBlockView.as_view(runtime=self.runtime,operation="plan")(
                self.request("plan",json.dumps(plan)))
        self.assertEqual(response.status_code,200,response.content)
        body=json.loads(response.content)
        self.assertEqual(body["missing"],[self.block_id])
        self.assertEqual(body["intent_id"],self.intent)
        self.assertNotIn("native_user",body)

    @override_settings(CLOUDFILE_AGENT2_CDC_ENABLED=True)
    def test_foreign_missing_blocks_fail_closed(self):
        plan=dict(file_id="f"*40,size=len(self.payload),sha256=self.grant["content_digest"])
        with patch("cloudfile_extensions.local_edit.block_http._native_repo",return_value="a"*40), (
             patch("cloudfile_extensions.local_edit.block_http._read_blocks",
                   return_value=(plan,[self.block_id],{self.block_id:len(self.payload)}))), (
             patch("cloudfile_extensions.local_edit.block_http._call",
                   return_value=json.dumps(["b"*40]))):
            response=AgentBlockView.as_view(runtime=self.runtime,operation="plan")(
                self.request("plan",json.dumps(plan)))
        self.assertEqual(response.status_code,503)

    @override_settings(CLOUDFILE_AGENT2_CDC_ENABLED=True)
    def test_stage_checks_digest_and_does_not_publish(self):
        sizes={self.block_id:len(self.payload)}
        with TemporaryDirectory() as temp:
            Path(temp,"httptemp").mkdir()
            with patch.dict(os.environ,{"SEAFILE_DATA_DIR":temp}), (
                 patch("cloudfile_extensions.local_edit.block_http._native_repo",return_value="a"*40)), (
                 patch("cloudfile_extensions.local_edit.block_http._read_blocks",
                       return_value=({},[self.block_id],sizes))), (
                 patch("cloudfile_extensions.local_edit.block_http._call",return_value=0)) as rpc:
                response=AgentBlockView.as_view(runtime=self.runtime,operation="stage")(
                    self.request("stage",self.payload,"application/octet-stream",
                                 HTTP_X_CLOUDFILE_BLOCK_ID=self.block_id))
                self.assertEqual(response.status_code,200,response.content)
                self.assertEqual(rpc.call_args[0][0],"seafile_cloudfile_stage_raw_block")
                wrong=AgentBlockView.as_view(runtime=self.runtime,operation="stage")(
                    self.request("stage",b"0"*len(self.payload),"application/octet-stream",
                                 HTTP_X_CLOUDFILE_BLOCK_ID=self.block_id))
                self.assertEqual(wrong.status_code,400)
                self.assertEqual(rpc.call_count,1)
                self.assertEqual(list(Path(temp,"httptemp").iterdir()),[])

    def test_disabled_and_cookie_never_accept_device_grant(self):
        body=json.dumps(dict(file_id="f"*40))
        self.assertEqual(AgentBlockView.as_view(runtime=self.runtime,operation="plan")(
            self.request("plan",body)).status_code,503)
        with override_settings(CLOUDFILE_AGENT2_CDC_ENABLED=True):
            req=self.request("plan",body,HTTP_COOKIE="sid=secret")
            self.assertEqual(AgentBlockView.as_view(runtime=self.runtime,operation="plan")(req).status_code,503)

    @override_settings(CLOUDFILE_AGENT2_CDC_ENABLED=True)
    def test_unknown_publication_never_claims_success(self):
        value=dict(file_id="f"*40,size=len(self.payload),sha256=self.grant["content_digest"])
        with patch("cloudfile_extensions.local_edit.block_http._read_blocks",
                   return_value=(value,[self.block_id],{self.block_id:len(self.payload)})), (
             patch("cloudfile_extensions.local_edit.block_http._native_repo",return_value="b"*40)), (
             patch("cloudfile_extensions.local_edit.block_http._call",return_value=value["file_id"])):
            response=AgentBlockView.as_view(runtime=self.runtime,operation="publish")(
                self.request("publish",b"","application/octet-stream"))
        self.assertEqual(response.status_code,503)
        self.assertNotIn("published",response.content.decode().lower())


if __name__=="__main__":
    unittest.main()
