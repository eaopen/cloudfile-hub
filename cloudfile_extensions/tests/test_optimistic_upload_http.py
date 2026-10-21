"""Optimistic Agent2 signed raw upload HTTP adapter, no exclusive lease."""
import hashlib
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from django.conf import settings
if not settings.configured:
    settings.configure(SECRET_KEY="optimistic-upload-fixture",DEFAULT_CHARSET="utf-8")
from django.test import RequestFactory

from cloudfile_extensions.local_edit.agent_runtime import AgentClaimRuntime
from cloudfile_extensions.local_edit.optimistic_upload_http import AgentOptimisticUploadView
from cloudfile_extensions.identity.ticket_transport import NativeVersionConflict


class FixtureRuntime(AgentClaimRuntime):
    def __init__(self, grant):
        self.grant = grant
        self.published = None

    def optimistic_upload_receipt(self, grant, request_id):
        return dict(intent_id=self.grant["intent_id"],
            state="published" if self.published else "prepared",
            base_file_id=self.grant["condition"]["expected_file_id"],
            content_digest=self.grant["content_digest"],
            snapshot_size=self.grant["snapshot_size"],
            result_file_id=self.published)

    def optimistic_upload_grant(self, ticket, request_id):
        if ticket != "one-time-optimistic":
            raise ValueError("Invalid device")
        return self.grant


class OptimisticHTTPTests(unittest.TestCase):
    def setUp(self):
        self.raw=b"edited drawing STEP bytes"
        self.intent="11111111-1111-4111-8111-111111111111"
        self.repo="22222222-2222-4222-8222-222222222222"
        self.base="a"*40
        self.condition=dict(path="/library/file.step",
          context=dict(provider="fixture",userId="employee",epoch="e"*32),
          scopes=[],expected_file_id=self.base,
          agent_upload=dict(session_id="33333333-3333-4333-8333-333333333333",
              device_id="44444444-4444-4444-8444-444444444444",
              device_revision="2",session_revision="2"))
        self.grant=dict(instance="https://cloudfile.invalid",condition=self.condition,
           repo_id=self.repo,native_user="native@example.test",intent_id=self.intent,
           content_digest=hashlib.sha256(self.raw).hexdigest(),
           snapshot_size=len(self.raw),action="optimistic-update")
        self.runtime=FixtureRuntime(self.grant)
        self.view=AgentOptimisticUploadView.as_view(runtime=self.runtime)

    def request(self,raw=None,*,cookie=False,ident=None):
        obj=RequestFactory().post("/local-edit/upload",
            data=self.raw if raw is None else raw,
            content_type="application/octet-stream",secure=True,
            HTTP_AUTHORIZATION="Bearer one-time-optimistic",
            HTTP_IDEMPOTENCY_KEY=ident or self.intent)
        if not cookie:obj.META.pop("HTTP_COOKIE",None)
        return obj

    def test_original_file_target_and_digest_sent_to_native(self):
        with TemporaryDirectory() as temp:
            Path(temp,"httptemp").mkdir()
            def native(method,arguments,deadline):
                if method=="seafile_get_repo":
                    self.assertEqual(arguments,(self.repo,))
                    return {"head_cmmt_id":"f"*40}
                self.assertEqual(method,"seafile_cloudfile_put_file_with_barriers")
                repo,path,parent,name,user,condition=arguments
                self.assertEqual((repo,parent,name,user),
                  (self.repo,"/library","file.step","native@example.test"))
                self.assertEqual(Path(path).read_bytes(),self.raw)
                data=json.loads(condition)
                self.assertEqual(data["expected_file_id"],self.base)
                self.assertEqual(data["head_id"],"f"*40)
                self.assertEqual(data["agent_upload"],self.condition["agent_upload"])
                self.assertNotIn("oidc_session",data)
                self.assertNotIn("editing",data)
                self.runtime.published="b"*40
                return "b"*40
            with patch.dict(os.environ,{"SEAFILE_DATA_DIR":temp}), (
                patch("cloudfile_extensions.local_edit.optimistic_upload_http._call",
                      side_effect=native)):
                result=self.view(self.request())
            self.assertEqual(result.status_code,200,result.content)
            body=json.loads(result.content)
            self.assertEqual((body["state"],body["result_file_id"],body["base_file_id"]),
                             ("published","b"*40,self.base))
            self.assertEqual(list(Path(temp,"httptemp").iterdir()),[])

    def test_original_published_receipt_replay_never_publishes_again(self):
        self.runtime.published="c"*40
        with TemporaryDirectory() as temp:
            Path(temp,"httptemp").mkdir()
            with patch.dict(os.environ,{"SEAFILE_DATA_DIR":temp}):
                with patch("cloudfile_extensions.local_edit.optimistic_upload_http._call") as native:
                    response=self.view(self.request())
            self.assertEqual(response.status_code,200,response.content)
            self.assertEqual(json.loads(response.content)["result_file_id"],"c"*40)
            native.assert_not_called()

    def test_stale_version_returns_conflict_without_fake_success(self):
        with TemporaryDirectory() as temp:
            Path(temp,"httptemp").mkdir()
            def native(method,arguments,deadline):
                if method=="seafile_get_repo":return {"head_cmmt_id":"f"*40}
                raise NativeVersionConflict("original file is stale")
            with patch.dict(os.environ,{"SEAFILE_DATA_DIR":temp}), (
                patch("cloudfile_extensions.local_edit.optimistic_upload_http._call",
                      side_effect=native)):
                response=self.view(self.request())
            self.assertEqual(response.status_code,409,response.content)
            self.assertEqual(json.loads(response.content)["code"],"RESOURCE_VERSION_CONFLICT")

    def test_lost_native_reply_never_reports_published(self):
        with TemporaryDirectory() as temp:
            Path(temp,"httptemp").mkdir()
            with patch.dict(os.environ,{"SEAFILE_DATA_DIR":temp}), (
                patch("cloudfile_extensions.local_edit.optimistic_upload_http._call",
                      side_effect=[{"head_cmmt_id":"f"*40},TimeoutError("lost ACK")])):
                response=self.view(self.request())
            self.assertEqual(response.status_code,503,response.content)
            self.assertEqual(json.loads(response.content)["code"],"PUBLICATION_UNCONFIRMED")

    def test_cookie_wrong_content_or_intent_never_calls_native(self):
        with patch("cloudfile_extensions.local_edit.optimistic_upload_http._call") as native:
            self.assertNotEqual(self.view(self.request(cookie=True)).status_code,200)
            self.assertNotEqual(self.view(self.request(raw=b"X"*len(self.raw))).status_code,200)
            self.assertNotEqual(self.view(self.request(ident="5"*36)).status_code,200)
            native.assert_not_called()


if __name__=="__main__":
    unittest.main()
