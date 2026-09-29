"""Administrator audit paging against an isolated MySQL schema."""

import sys
import types
from types import SimpleNamespace
from datetime import datetime
from unittest.mock import patch

from django.test import RequestFactory, override_settings

from cloudfile_extensions.schema.runner import SchemaRunner
from cloudfile_extensions.tests.test_schema import DatabaseTestCase


class AdminAuditTests(DatabaseTestCase):
    @classmethod
    def setUpClass(cls):
        from django.conf import settings
        if not settings.configured:
            settings.configure(SECRET_KEY="test-only", DEFAULT_CHARSET="utf-8",
                               ALLOWED_HOSTS=["testserver"])
        import django
        django.setup()
        from rest_framework.authentication import BaseAuthentication
        from rest_framework.throttling import BaseThrottle
        authentication = types.ModuleType("seahub.api2.authentication")
        authentication.TokenAuthentication = type("TokenAuthentication", (BaseAuthentication,), {
            "authenticate": lambda self, request: None})
        throttling = types.ModuleType("seahub.api2.throttling")
        throttling.UserRateThrottle = type("UserRateThrottle", (BaseThrottle,), {
            "allow_request": lambda self, request, view: True})
        models = types.ModuleType("seahub.sysadmin_extra.models")
        models.UserLoginLog = type("UserLoginLog", (), {})
        with patch.dict(sys.modules, {authentication.__name__: authentication,
                                      throttling.__name__: throttling, models.__name__: models}):
            from cloudfile_extensions.events import admin
            cls.audit = admin

    def setUp(self):
        super().setUp()
        SchemaRunner(self.connection).apply()
        self.repo = "11111111-1111-4111-8111-111111111111"
        self.scope = {"category": "access", "start": "2026-09-01T00:00:00Z",
                      "end": "2026-09-30T00:00:00Z", "repo_id": None, "actor": None}
        self.configuration = override_settings(
            CLOUDFILE_POLICY_CONFIG={"database": {"host": self.options["host"], "port": self.options["port"],
                "user": "root", "password": "", "name": self.database}},
            CLOUDFILE_AUDIT_CURSOR_SECRET=b"test-only-admin-cursor-secret-with-32-bytes")
        self.configuration.enable()

    def tearDown(self):
        self.configuration.disable()
        super().tearDown()

    def _page(self, scope, limit=100, position=None):
        import pymysql
        with patch.dict(sys.modules, {"MySQLdb": pymysql}):
            return self.audit._event_page(scope, limit, position)

    def test_global_categories_filters_and_pagination(self):
        with self.connection.cursor() as sql:
            sql.executemany(
                "INSERT INTO cf_audit_event(repo_id,object_type,object_id,operation,operator,source,result,occurred_at,source_path) "
                "VALUES(%s,'file','',%s,%s,'hub','succeeded',%s,'/doc')",
                [(self.repo, "file.download", "alice", "2026-09-12"),
                 (self.repo, "file.view", "bob", "2026-09-11"),
                 (self.repo, "file.upload", "alice", "2026-09-10"),
                 (self.repo, "admin.created", "alice", "2026-09-09")])
        first = self._page(self.scope, limit=1)
        self.assertEqual([item["operation"] for item in first["items"]], ["file.download"])
        position = self.audit._decode_cursor(first["next_cursor"], self.scope)
        self.assertEqual([item["operation"] for item in self._page(self.scope, limit=1, position=position)["items"]],
                         ["file.view"])
        self.assertEqual([item["operation"] for item in self._page(dict(self.scope, category="updates"))["items"]],
                         ["file.upload"])
        self.assertEqual([item["operation"] for item in self._page(dict(self.scope, category="permissions"))["items"]],
                         ["admin.created"])
        self.assertEqual([item["operation"] for item in self._page(dict(self.scope, actor="bob"))["items"]],
                         ["file.view"])
        self.assertEqual(self._page(dict(self.scope, repo_id="22222222-2222-4222-8222-222222222222"))["items"], [])

    def test_cursor_cannot_change_category_or_filters(self):
        cursor = self.audit._encode_cursor(self.scope, ["2026-09-12T00:00:00Z", 1])
        with self.assertRaises(ValueError):
            self.audit._decode_cursor(cursor, dict(self.scope, category="updates"))
        with self.assertRaises(ValueError):
            self.audit._decode_cursor(cursor[:-1] + "!", self.scope)
        request = RequestFactory().get("/audit/", {"start": "2026-09-01T00:00:00Z",
            "end": "2026-10-03T00:00:00Z"})
        with self.assertRaises(ValueError):
            self.audit._query_options(request, "access")

    def test_system_admin_role_and_log_permission_are_required(self):
        from rest_framework.test import APIRequestFactory, force_authenticate
        view = self.audit.CloudFileAdminAuditView.as_view()
        request = APIRequestFactory().get("/audit/", {"start": "2026-09-01T00:00:00Z",
            "end": "2026-09-02T00:00:00Z"})
        ordinary = SimpleNamespace(is_staff=False, is_authenticated=True)
        force_authenticate(request, user=ordinary)
        with override_settings(CLOUDFILE_AUDIT_QUERY_ENABLED=True):
            self.assertEqual(view(request, category="access").status_code, 403)
        request = APIRequestFactory().get("/audit/", {"start": "2026-09-01T00:00:00Z",
            "end": "2026-09-02T00:00:00Z"})
        restricted = SimpleNamespace(is_staff=True, is_authenticated=True,
            admin_permissions=SimpleNamespace(can_view_user_log=lambda: False))
        force_authenticate(request, user=restricted)
        with override_settings(CLOUDFILE_AUDIT_QUERY_ENABLED=True):
            self.assertEqual(view(request, category="access").status_code, 403)

    def test_login_rows_use_seahubs_naive_utc_storage(self):
        class Rows:
            def __init__(self):
                self.bounds = None

            def filter(self, *args, **kwargs):
                if kwargs.get("login_date__gte") is not None:
                    self.bounds = kwargs
                return self

            def order_by(self, *fields):
                return self

            def values(self, *fields):
                return self

            def __getitem__(self, key):
                return [{"id": 1, "username": "alice", "login_date": datetime(2026, 9, 12),
                         "login_ip": "192.0.2.10", "login_success": True}][key]

        rows = Rows()
        with patch.object(self.audit.UserLoginLog, "objects", rows, create=True):
            page = self.audit._login_page(dict(self.scope, category="login"), 100, None)
        self.assertIsNone(rows.bounds["login_date__gte"].tzinfo)
        self.assertEqual(page["items"][0]["occurred_at"], "2026-09-12T00:00:00Z")
