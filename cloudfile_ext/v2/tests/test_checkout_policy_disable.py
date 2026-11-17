"""Contract: a live native Checkout lease blocks capability removal atomically."""
from contextlib import nullcontext
from unittest import TestCase
from unittest.mock import MagicMock, Mock, patch

from cloudfile_ext.v2.http import RepoFeatures

REPO = "11111111-1111-4111-8111-111111111111"


class CheckoutDisableTests(TestCase):
    def request(self, changes, active):
        req = Mock(data=changes)
        req.user.admin_permissions.can_manage_library.return_value = True
        cursor = MagicMock()
        cursor.fetchone.side_effect = [("valid-master-head",), (1,) if active else None]
        cursor.fetchall.side_effect = [[("checkout",)], []]
        conn = MagicMock()
        conn.cursor.return_value.__enter__.return_value = cursor
        with patch("django.db.connection", conn), \
             patch("django.db.transaction.atomic", return_value=nullcontext()), \
             patch("seahub.utils.db_api.SeafileDB") as db:
            db.return_value.db_name = "seafile_db"
            result = RepoFeatures().post(req, REPO)
        statements = [call.args[0] for call in cursor.execute.call_args_list]
        return result, statements

    def test_active_checkout_refuses_all_feature_changes_before_any_write(self):
        response, queries = self.request({"checkout": False, "protection": True}, active=True)
        self.assertEqual(response.status_code, 409)
        self.assertTrue(any("cf_edit_guard" in sql and "lease_expires_at>UTC_TIMESTAMP(6)" in sql
                            and "FOR UPDATE" in sql for sql in queries))
        self.assertFalse(any(sql.startswith(("INSERT", "DELETE", "UPDATE")) for sql in queries))

    def test_no_live_checkout_allows_atomic_disable(self):
        response, queries = self.request({"checkout": False}, active=False)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["features"], [])
        self.assertTrue(any(sql.startswith("DELETE") and "cf_repo_feature" in sql for sql in queries))

    def test_expired_or_empty_guard_does_not_block(self):
        response, queries = self.request({"checkout": False}, active=False)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(any("lease_expires_at>UTC_TIMESTAMP(6)" in sql for sql in queries))

    def test_unknown_readiness_refuses_mixed_patch_before_disable(self):
        with patch("cloudfile_ext.v2.writer_runtime.writer_runtime",
                   return_value={"checkout": "ready", "protection": "unknown"}):
            response, queries = self.request({"checkout": False, "protection": True}, active=False)
        self.assertEqual(response.status_code, 503)
        self.assertFalse(any(sql.startswith(("INSERT", "DELETE", "UPDATE")) for sql in queries))

    def test_only_actual_transitions_are_audited(self):
        response, queries = self.request({"checkout": False}, active=False)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(sum("INSERT INTO" in sql and "cf_audit_event" in sql for sql in queries), 1)
        with patch("cloudfile_ext.v2.writer_runtime.writer_runtime", return_value={"checkout": "unknown"}):
            response, queries = self.request({"checkout": True}, active=False)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(any("cf_audit_event" in sql for sql in queries))
