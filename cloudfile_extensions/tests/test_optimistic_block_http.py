"""Shared Hub CDC HTTP adapter has mode-specific credentials and one native finalizer."""
import hashlib
import json
import unittest
from unittest.mock import patch
from django.conf import settings
if not settings.configured:
    settings.configure(SECRET_KEY="cdc-mode-fixture",DEFAULT_CHARSET="utf-8")
from django.test import RequestFactory,override_settings

from cloudfile_extensions.local_edit.block_http import AgentBlockView
from cloudfile_extensions.tests.test_optimistic_upload_http import FixtureRuntime


class OptimisticBlockHTTPTests(unittest.TestCase):
    def setUp(self):
        self.payload=b"CAD binary delta block"
        self.bid=hashlib.sha1(self.payload).hexdigest()
        self.intent="11111111-1111-4111-8111-111111111111"
        self.repo="22222222-2222-4222-8222-222222222222"
        self.file="a"*40
        self.condition=dict(path="/drawing.dwg",expected_file_id=self.file,
            context=dict(provider="current",userId="employee",epoch="d"*32),
            scopes=[],agent_upload=dict(session_id="33333333-3333-4333-8333-333333333333",
                  device_id="44444444-4444-4444-8444-444444444444",
                  device_revision="2",session_revision="2",intent_id=self.intent))
        self.grant=dict(instance="https://cloudfile.invalid",condition=self.condition,
            repo_id=self.repo,native_user="user@example.test",intent_id=self.intent,
            content_digest=hashlib.sha256(self.payload).hexdigest(),
            snapshot_size=len(self.payload),action="optimistic-update")
        self.runtime=FixtureRuntime(self.grant)

    def request(self,operation,raw,media="application/json"):
        request=RequestFactory().post("/v1/agent/optimistic-block-"+operation+"/",
            data=raw,content_type=media,secure=True,
            HTTP_AUTHORIZATION="Bearer one-time-optimistic",
            HTTP_IDEMPOTENCY_KEY=self.intent)
        request.META.pop("HTTP_COOKIE",None)
        return request

    @override_settings(CLOUDFILE_AGENT2_CDC_ENABLED=True)
    def test_original_optimistic_device_block_plan(self):
        plan=dict(file_id="f"*40,size=len(self.payload),
            sha256=self.grant["content_digest"],
            blocks=[dict(id=self.bid,size=len(self.payload))])
        with patch("cloudfile_extensions.local_edit.block_http._native_repo",return_value="e"*40), (
             patch("cloudfile_extensions.local_edit.block_http._read_blocks",
                   return_value=(plan,[self.bid],{self.bid:len(self.payload)}))), (
             patch("cloudfile_extensions.local_edit.block_http._call",
                   return_value=json.dumps([self.bid]))):
            response=AgentBlockView.as_view(runtime=self.runtime,operation="plan",
                optimistic=True)(self.request("plan",json.dumps(plan)))
        self.assertEqual(response.status_code,200,response.content)
        result=json.loads(response.content)
        self.assertEqual(result["missing"],[self.bid])
        self.assertEqual(result["intent_id"],self.intent)

    @override_settings(CLOUDFILE_AGENT2_CDC_ENABLED=True)
    def test_optimistic_cdc_native_dispatch_requires_same_durable_receipt(self):
        plan=dict(file_id="f"*40,size=len(self.payload),
            sha256=self.grant["content_digest"])
        def native(method,args,deadline):
            if method!="seafile_cloudfile_publish_optimistic_blocks":
                self.fail("Unsafe or wrong Native publication RPC")
            self.assertEqual(args[0],self.repo)
            self.assertEqual(args[3],"/")
            self.assertEqual(args[4],"drawing.dwg")
            condition=json.loads(args[6])
            self.assertEqual(condition["agent_upload"]["intent_id"],self.intent)
            self.runtime.published=plan["file_id"]
            return plan["file_id"]
        with patch("cloudfile_extensions.local_edit.block_http._native_repo",return_value="e"*40), (
             patch("cloudfile_extensions.local_edit.block_http._read_blocks",
                   return_value=(plan,[self.bid],{self.bid:len(self.payload)}))), (
             patch("cloudfile_extensions.local_edit.block_http._call",side_effect=native)):
            response=AgentBlockView.as_view(runtime=self.runtime,operation="publish",
                optimistic=True)(self.request("publish",b"","application/octet-stream"))
        self.assertEqual(response.status_code,200,response.content)
        result=json.loads(response.content)["intent"]
        self.assertEqual(result["state"],"published")
        self.assertEqual(result["result_file_id"],plan["file_id"])
        self.assertEqual(result["base_file_id"],self.file)

    def test_default_disabled_even_with_device_grant(self):
        response=AgentBlockView.as_view(runtime=self.runtime,operation="plan",
            optimistic=True)(self.request("plan",b"{}"))
        self.assertEqual(response.status_code,503)
