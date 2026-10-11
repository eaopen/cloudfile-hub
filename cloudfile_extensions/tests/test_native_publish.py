"""The three upload entries reuse Seafile, not a new file publication engine.

Checks the existing Web OIDC condition shape, explicit Web head fence,
and two distinct device credentials routed to Seafile's native methods.
"""
import json
import unittest

from cloudfile_extensions.local_edit.native_publish import (
    native_head, native_target, full_native_publish, cdc_native_publish)


class NativePublishCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.repo = "11111111-1111-4111-8111-111111111111"
        self.web_head = "a" * 40
        self.fresh_head = "b" * 40
        self.result_file = "c" * 40

    def rpc(self, method, arguments, deadline):
        self.calls.append((method, arguments))
        if method == "seafile_get_repo":
            self.assertEqual(arguments, (self.repo,))
            return {"head_cmmt_id": self.fresh_head}
        self.assertEqual(len(arguments), 6)
        self.assertEqual(arguments[:5], (self.repo, "/trusted/private-staging",
                                          "/docs", "drawing.dwg", "native-user"))
        return self.result_file

    def test_web_explicit_head_and_legacy_shape_never_change(self):
        conditions = dict(head_id=self.web_head, context=dict(provider="oidc"),
                          scopes=[1, 2], oidc_session={"scope_hash": "legacy"})
        original = json.loads(json.dumps(conditions))
        result = full_native_publish(call=self.rpc, repo=self.repo,
            staged="/trusted/private-staging", user="native-user",
            condition=conditions, target_path="/docs/drawing.dwg",
            mode="web", head=self.web_head)
        self.assertEqual(result, self.result_file)
        self.assertEqual(conditions, original)
        self.assertEqual(len(self.calls), 1, "Web must not silently refresh its HEAD")
        self.assertEqual(self.calls[0][0], "seafile_cloudfile_put_file_with_barriers")
        outgoing = json.loads(self.calls[0][1][5])
        self.assertEqual(outgoing, original)
        self.assertNotIn("path", outgoing, "Seafile put_file_rpc injects canonical target")

    def test_web_rejects_stale_or_mismatched_selected_head_before_rpc(self):
        conditions = dict(head_id=self.web_head, scopes=[1, 2],
                          oidc_session={"scope_hash": "legacy"})
        with self.assertRaises(Exception):
            full_native_publish(call=self.rpc, repo=self.repo,
                staged="/trusted/private-staging", user="native-user",
                condition=conditions, target_path="/docs/drawing.dwg",
                mode="web", head="d"*40)
        self.assertEqual(self.calls, [])

    def test_optimistic_native_only_receives_original_session_condition(self):
        conditions = dict(path="/docs/drawing.dwg",
            agent_upload=dict(device_id="paired", intent_id="original"),
            expected_file_id="d"*40, context={}, scopes=[])
        result = full_native_publish(call=self.rpc, repo=self.repo,
            staged="/trusted/private-staging",user="native-user",
            condition=conditions,mode="optimistic")
        self.assertEqual(result, self.result_file)
        self.assertEqual([x[0] for x in self.calls],
                         ["seafile_get_repo", "seafile_cloudfile_put_file_with_barriers"])
        wrapped = json.loads(self.calls[1][1][5])
        self.assertEqual(wrapped["head_id"], self.fresh_head)
        self.assertEqual(wrapped["agent_upload"], conditions["agent_upload"])
        self.assertNotIn("head_id", conditions)
        self.assertNotIn("editing", wrapped)

    def test_checkout_still_uses_existing_native_publish_edit(self):
        conditions = dict(path="/docs/drawing.dwg", editing={"guard_id": "guard"},
            local_commit={"device_id": "paired"},context={},scopes=[])
        result = full_native_publish(call=self.rpc, repo=self.repo,
            staged="/trusted/private-staging",user="native-user",
            condition=conditions,mode="exclusive")
        self.assertEqual(result, self.result_file)
        self.assertEqual(self.calls[1][0], "seafile_cloudfile_publish_edit")
        self.assertEqual(json.loads(self.calls[1][1][5])["head_id"], self.fresh_head)
        self.assertNotIn("agent_upload", conditions)

    def test_mixed_modes_or_changed_path_cannot_enter_native(self):
        for mode, value in [
            ("web",dict(path="/docs/drawing.dwg",oidc_session={},agent_upload={})),
            ("optimistic",dict(path="/docs/drawing.dwg",agent_upload={},editing={},expected_file_id="d"*40)),
            ("exclusive",dict(path="/docs/drawing.dwg",editing={},local_commit={},agent_upload={})),
        ]:
            with self.subTest(mode=mode), self.assertRaises(Exception):
                full_native_publish(call=self.rpc, repo=self.repo,
                    staged="/trusted/private-staging",user="native-user",
                    condition=value,mode=mode,target_path="/docs/drawing.dwg",
                    head=self.web_head)
        with self.assertRaises(Exception):
            full_native_publish(call=self.rpc, repo=self.repo,
                staged="/trusted/private-staging",user="native-user",
                condition={"path":"/docs/wrong.dwg","expected_file_id":"d"*40,
                           "agent_upload":{}},mode="optimistic",
                target_path="/docs/drawing.dwg")
        self.assertEqual(self.calls, [])

    def test_seafile_head_alias_and_invalid_target_fail_closed(self):
        self.assertEqual(native_head({"head-cmmt-id":self.fresh_head}),self.fresh_head)
        for meta in ({}, {"head_cmmt_id":"BAD"}, {"head_cmmt_id":self.fresh_head,
            "head-cmmt-id":self.fresh_head}):
            with self.assertRaises(Exception):
                native_head(meta)
        for target in ("/", "/docs/", "/docs//secret", "/docs/../", "/docs/.",
                       "/docs/\x00secret"):
            with self.assertRaises(Exception):
                native_target(target)


    def test_cdc_shares_native_target_but_not_agent_authority(self):
        blocks = ["d"*40, "e"*40]
        base = dict(path="/docs/drawing.dwg",context={},scopes=[],
                    expected_file_id="f"*40)
        for mode, proof, expected in (
            ("optimistic",dict(agent_upload={"intent_id":"original"}),
             "seafile_cloudfile_publish_optimistic_blocks"),
            ("exclusive",dict(editing={"guard_id":"guard"},
                              local_commit={"session_id":"session"}),
             "seafile_cloudfile_publish_edit_blocks"),
        ):
            with self.subTest(mode=mode):
                calls = []
                def call(method,arguments,deadline):
                    calls.append((method,arguments))
                    return self.result_file
                condition = dict(base, **proof)
                before = json.loads(json.dumps(condition))
                result = cdc_native_publish(call=call,repo=self.repo,
                    ordered=blocks,size=100,user="native-user",condition=condition,
                    mode=mode,head=self.fresh_head)
                self.assertEqual(result,self.result_file)
                self.assertEqual(calls[0][0],expected)
                self.assertEqual(calls[0][1][0],self.repo)
                self.assertEqual(json.loads(calls[0][1][1]),blocks)
                self.assertEqual(calls[0][1][3:5],("/docs","drawing.dwg"))
                self.assertEqual(json.loads(calls[0][1][-1])["head_id"],self.fresh_head)
                self.assertEqual(condition,before,"no in-place mutation of signed conditions")
        with self.assertRaises(Exception):
            cdc_native_publish(call=self.rpc,repo=self.repo,ordered=blocks,
                size=100,user="native-user",condition=base,mode="web",head=self.web_head)
        with self.assertRaises(Exception):
            cdc_native_publish(call=self.rpc,repo=self.repo,ordered=["NOT-BLOCK"],
                size=100,user="native-user",condition=dict(base,agent_upload={}),
                mode="optimistic",head=self.fresh_head)
