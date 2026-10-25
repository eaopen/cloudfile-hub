"""Scope tests: view tickets require read, and cannot be upgraded to write."""
import stat
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlsplit, parse_qs

import jwt
from rest_framework.test import APIRequestFactory, force_authenticate

from cloudfile_ext.v2.rust_edit import (RustLocalEditOpen, RustCheckoutInfo,
                                        issue_ticket, checkout_available, checkout_for_repo)


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
        # Mirror the real CE14 binding: dirents expose obj_id/obj_name, not `.id`.
        # A fixture with `.id` hides exactly this class of bug (it shipped once).
        file_entry = SimpleNamespace(mode=stat.S_IFREG | 0o644, obj_id=FILE_ID)
        # Scope denial is tested with Checkout installed; schema discovery has
        # its own tests and must not turn this authorization case into HTTP 503.
        with patch("cloudfile_ext.v2.rust_edit.checkout_for_repo", return_value=True), \
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


class CheckoutCapabilityTests(unittest.TestCase):
    def test_checkout_is_off_without_explicit_repo_selection(self):
        with patch('cloudfile_ext.v2.rust_edit.settings',
                   SimpleNamespace(CF_CHECKOUT_REPOS=())), \
             patch('cloudfile_ext.v2.rust_edit.checkout_available') as available:
            self.assertFalse(checkout_for_repo(RID))
            available.assert_not_called()

    def test_checkout_only_for_selected_repo(self):
        with patch('cloudfile_ext.v2.rust_edit.settings',
                   SimpleNamespace(CF_CHECKOUT_REPOS=(RID,))), \
             patch('cloudfile_ext.v2.rust_edit.checkout_available', return_value=True):
            self.assertTrue(checkout_for_repo(RID))
            self.assertFalse(checkout_for_repo('22222222-2222-4222-8222-222222222222'))

    def test_selected_repo_is_still_off_when_global_capability_is_disabled(self):
        with patch('cloudfile_ext.v2.rust_edit.settings',
                   SimpleNamespace(CF_CHECKOUT_REPOS=(RID,))), \
             patch('cloudfile_ext.v2.rust_edit.checkout_available', return_value=False):
            self.assertFalse(checkout_for_repo(RID))

    def test_malformed_selection_type_fails_safe_to_off(self):
        with patch('cloudfile_ext.v2.rust_edit.settings',
                   SimpleNamespace(CF_CHECKOUT_REPOS=RID)), \
             patch('cloudfile_ext.v2.rust_edit.checkout_available') as available:
            self.assertFalse(checkout_for_repo(RID))
            available.assert_not_called()

    def test_off_repo_lock_info_never_queries_guard(self):
        req = APIRequestFactory().get('/api/v2.1/cloudfile/edit/v1/lock-info/',
                                      {'repo_id': RID, 'path': FILE})
        force_authenticate(req, SimpleNamespace(username='reader@auth.local',
                                                 is_authenticated=True, is_active=True))
        with patch('cloudfile_ext.v2.rust_edit.checkout_for_repo', return_value=False), \
             patch('cloudfile_ext.v2.rust_edit.connection') as database:
            response = RustCheckoutInfo.as_view()(req)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data['checkout_supported'], False)
            database.cursor.assert_not_called()


    def test_disabled_checkout_never_discovers_schema(self):
        checkout_available.cache_clear()
        try:
            with patch('cloudfile_ext.features.is_enabled', return_value=False), \
                 patch('cloudfile_ext.v2.checkout_schema.path_checkout_available') as qualify:
                self.assertFalse(checkout_available())
                qualify.assert_not_called()
        finally:
            checkout_available.cache_clear()

    def test_enabled_checkout_still_qualifies_the_guard(self):
        checkout_available.cache_clear()
        try:
            with patch('cloudfile_ext.features.is_enabled', return_value=True), \
                 patch('seahub.utils.db_api.SeafileDB') as database, \
                 patch('cloudfile_ext.v2.checkout_schema.path_checkout_available', return_value=True) as qualify:
                database.return_value.db_name='fixture_files'
                self.assertTrue(checkout_available())
                self.assertEqual(qualify.call_args.args[1], 'fixture_files')
        finally:
            checkout_available.cache_clear()
