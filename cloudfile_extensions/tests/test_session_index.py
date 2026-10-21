"""Actual isolated index SQL; does not exercise Django session deletion."""
from dataclasses import replace
from datetime import datetime, timezone

from cloudfile_extensions.identity.logout_token import LogoutNotification
from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.identity.session_index import OIDCSessionIndex
from cloudfile_extensions.schema.runner import SchemaRunner
from cloudfile_extensions.tests.test_schema import DatabaseTestCase


class SessionIndexTests(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        SchemaRunner(self.connection).apply()
        self.index = OIDCSessionIndex(self.connection, issuer="https://idp.invalid/", client_id="cloudfile")
        self.notification = LogoutNotification("https://idp.invalid/", "cloudfile", "jti", "subject", "sid", 1000, 1060)

    def register(self, cursor, letter, *, subject="subject", sid="sid", issued=900):
        self.index.register(cursor, session_key=letter * 32, subject=subject, session_id=sid,
            authenticated_at=issued, expires_at=datetime(2050, 1, 1, tzinfo=timezone.utc))

    def test_sid_subject_and_newer_authentication_boundaries(self):
        self.connection.begin()
        try:
            with self.connection.cursor() as cursor:
                self.register(cursor, "a")
                self.register(cursor, "b", issued=1001)
                self.register(cursor, "c", subject="other")
                self.register(cursor, "d", sid="different")
                self.assertEqual(self.index.targets(cursor, self.notification), ("a" * 32,))
                subject_only = replace(self.notification, session_id=None)
                self.assertEqual(self.index.targets(cursor, subject_only), ("a" * 32, "d" * 32))
                self.index.forget(cursor, "a" * 32)
                self.assertEqual(self.index.targets(cursor, self.notification), ())
            self.connection.commit()
        finally:
            self.connection.rollback()

    def test_register_rollback_leaves_no_reference(self):
        self.connection.begin()
        with self.connection.cursor() as cursor:
            self.register(cursor, "a")
        self.connection.rollback()
        self.connection.begin()
        try:
            with self.connection.cursor() as cursor:
                self.assertEqual(self.index.targets(cursor, self.notification), ())
        finally:
            self.connection.rollback()

    def test_logout_fence_is_monotonic_and_rejects_delayed_login(self):
        self.connection.begin()
        try:
            with self.connection.cursor() as cursor:
                self.index.fence(cursor, self.notification)
                self.index.fence(cursor, replace(self.notification, issued_at=950, expires_at=1010))
                for issued in (950, 1000):
                    with self.assertRaises(ContractError) as error:
                        self.register(cursor, "a", issued=issued)
                    self.assertEqual(error.exception.code, "AUTHENTICATION_REQUIRED")
                self.register(cursor, "b", issued=1001)
                self.register(cursor, "c", sid="another", issued=900)
                self.assertEqual(self.index.targets(cursor, self.notification), ())
            self.connection.commit()
        finally:
            self.connection.rollback()

    def test_subject_fence_covers_other_sid_but_not_other_subject(self):
        self.connection.begin()
        try:
            with self.connection.cursor() as cursor:
                self.index.fence(cursor, replace(self.notification, session_id=None))
                with self.assertRaises(ContractError):
                    self.register(cursor, "a", sid="another", issued=1000)
                self.register(cursor, "b", subject="other", issued=900)
            self.connection.commit()
        finally:
            self.connection.rollback()

    def test_no_effect_without_caller_transaction(self):
        with self.connection.cursor() as cursor:
            with self.assertRaises(ValueError):
                self.register(cursor, "a")

    def test_fixed_scope_and_page_budget_required(self):
        self.connection.begin()
        try:
            with self.connection.cursor() as cursor:
                for notification, limit in ((replace(self.notification, client_id="other"), 100),
                        (self.notification, 0), (self.notification, 1001)):
                    with self.assertRaises(ValueError):
                        self.index.targets(cursor, notification, limit=limit)
        finally:
            self.connection.rollback()
