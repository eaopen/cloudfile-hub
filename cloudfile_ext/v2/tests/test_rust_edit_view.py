"""Scope tests: view tickets require read, and cannot be upgraded to write."""
import stat
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlsplit, parse_qs

import jwt
from rest_framework.test import APIRequestFactory, force_authenticate

from cloudfile_ext.v2.rust_edit import RustLocalEditOpen, issue_ticket


RID = "11111111-1111-4111-8111-111111111111"
FILE = "/report.pdf"
FILE_ID = "a" * 40


class ViewScopeTests(unittest.TestCase):
    def request(self, mode, *, read, write):
        req = APIRequestFactory().post(
            "/api/v2.1/cloudfile/edit/v1/open/",
            {"repo_id": RID, "path": FILE, "mode": mode}, format="json")
        force_authenticate(req, SimpleNamespace(username="reader@auth.local",
                                                 is_authenticated=True, is_active=True))
        policy = SimpleNamespace(can_read=read, can_write=write)
        repo = SimpleNamespace(is_virtual=False, encrypted=False, version=1)
        file_entry = SimpleNamespace(mode=stat.S_IFREG | 0o644, id=FILE_ID)
        # Scope denial is tested with Checkout installed; schema discovery has
        # its own tests and must not turn this authorization case into HTTP 503.
        with patch("cloudfile_ext.v2.rust_edit.checkout_available", return_value=True), \
             patch("cloudfile_ext.v2.rust_edit.Profile.objects.get",
                   return_value=SimpleNamespace(login_id="stable-uid")), \
             patch("cloudfile_ext.v2.rust_edit.Authority") as auth, \
             patch("cloudfile_ext.v2.rust_edit.seafile_api.get_repo", return_value=repo), \
             patch("cloudfile_ext.v2.rust_edit.seafile_api.get_dirent_by_path",
                   return_value=file_entry), \
             patch("cloudfile_ext.v2.rust_edit.JWT_PRIVATE_KEY", "unit-test-secret"):
            auth.return_value.effective.return_value = policy
            return RustLocalEditOpen.as_view()(req)

    def test_read_only_user_gets_local_view_but_not_edit_or_checkout(self):
        response = self.request("local-view", read=True, write=False)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["mode"], "local-view")
        query = parse_qs(urlsplit(response.data["open_uri"]).query)
        claims = jwt.decode(query["ticket"][0], "unit-test-secret",
                            audience="cloudfile-edit-agent", algorithms=["HS256"])
        self.assertEqual(claims["mode"], "local-view")
        self.assertEqual(claims["repo_id"], RID)
        self.assertEqual(claims["path"], FILE)
        self.assertEqual(claims["file_id"], FILE_ID)
        for mode in ("optimistic-edit", "exclusive-edit"):
            denied = self.request(mode, read=True, write=False)
            self.assertEqual(denied.status_code, 403)
            self.assertEqual(denied.data["code"], "EDIT_DENIED")

    def test_denied_view_cannot_get_token_even_if_request_is_well_formed(self):
        denied = self.request("local-view", read=False, write=False)
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(denied.data["code"], "VIEW_DENIED")

    def test_unknown_mode_does_not_bypass_guard_or_acl(self):
        denied = self.request("write-anything", read=True, write=True)
        self.assertEqual(denied.status_code, 400)

    def test_view_claim_is_issued_only_for_explicit_local_view(self):
        base = dict(username="reader@auth.local", uid="stable-uid",
                    repo_id=RID, path=FILE, file_id=FILE_ID, now=1700000000,
                    secret="unit-test-secret")
        self.assertTrue(issue_ticket(mode="local-view", **base))
        with self.assertRaises(ValueError):
            issue_ticket(mode="unlimited", **base)
