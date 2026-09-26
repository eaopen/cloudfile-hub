"""Real SQL reader tests; current authorization remains a trusted test adapter."""

from uuid import uuid4

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.events.outbox import EventWriter
from cloudfile_extensions.events.query import AuditReader
from cloudfile_extensions.schema.runner import SchemaRunner
from cloudfile_extensions.tests.test_schema import DatabaseTestCase


class AuditQueryTests(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        SchemaRunner(self.connection).apply()
        self.repo = "11111111-1111-4111-8111-111111111111"
        self.visible = True
        self.reader = AuditReader(self.connection, secret=b"test-only-audit-key-with-32-bytes!",
                                  authorize=lambda actor, row: self.visible and row.get("source_path") != "/hidden")
        self.arguments = dict(actor="reader", repo_id=self.repo,
                              start="2026-09-01T00:00:00Z", end="2026-10-01T00:00:00Z")
        for path in ("/first", "/hidden", "/last"):
            self.connection.begin()
            with self.connection.cursor() as sql:
                EventWriter().append(sql, {"event_id": str(uuid4()), "occurred_at": "2026-09-10T00:00:00Z",
                    "request_id": "request", "actor_user_id": "writer", "actor_kind": "user", "source": "hub",
                    "action": "file.updated", "result": "succeeded", "repo_id": self.repo, "path": path})
            self.connection.commit()

    def test_pagination_filters_and_no_raw_payload(self):
        first = self.reader.list(**self.arguments, limit=1)
        self.assertEqual(first["items"][0]["source_path"], "/last")
        self.assertNotIn("event_payload", first["items"][0])
        self.assertNotIn("total", first)
        next_page = self.reader.list(**self.arguments, limit=1, cursor=first["next_cursor"])
        self.assertEqual(next_page["items"][0]["source_path"], "/first")
        self.assertIsNone(next_page["next_cursor"])
        self.assertEqual(self.reader.list(**self.arguments, actor_user_id="absent")["items"], [])
        self.assertEqual(len(self.reader.list(**self.arguments, path="/last")["items"]), 1)
        self.assertEqual(self.reader.list(**self.arguments, resource_uid=str(uuid4()))["items"], [])

    def test_cursor_is_bound_and_current_revocation_overrides_it(self):
        token = self.reader.list(**self.arguments, limit=1)["next_cursor"]
        for change in ({"actor": "other"}, {"result": "failed"}, {"cursor": token[:-1] + "!"}):
            with self.assertRaises(ContractError) as caught:
                self.reader.list(**{**self.arguments, "cursor": token, **change})
            self.assertEqual(caught.exception.status, 400)
        self.visible = False
        with self.assertRaises(ContractError) as caught:
            self.reader.list(**self.arguments, cursor=token)
        self.assertEqual(caught.exception.status, 403)

    def test_hidden_candidate_budget_and_expired_cursor(self):
        with self.connection.cursor() as sql:
            sql.executemany("INSERT INTO cf_audit_event(repo_id,object_type,object_id,operation,operator,source,result,occurred_at,source_path) "
                            "VALUES(%s,'file','','update','writer','hub','succeeded','2026-09-12','/hidden')",
                            [(self.repo,)] * 1001)
        page = self.reader.list(**self.arguments)
        self.assertEqual(page["items"], [])
        self.assertIsNotNone(page["next_cursor"])
        continuation = self.reader.list(**self.arguments, cursor=page["next_cursor"])
        self.assertEqual(len(continuation["items"]), 2)
        now = self.reader.clock()
        self.reader.clock = lambda: now + 901
        with self.assertRaises(ContractError) as caught:
            self.reader.list(**self.arguments, cursor=page["next_cursor"])
        self.assertEqual(caught.exception.status, 400)

    def test_legacy_identity_is_not_fabricated_and_faults_are_sanitized(self):
        with self.connection.cursor() as sql:
            sql.execute("INSERT INTO cf_audit_event(repo_id,object_type,object_id,operation,operator,source,result,occurred_at) "
                        "VALUES(%s,'file','','update','old@example.invalid','api','success','2026-09-11')", (self.repo,))
        legacy = self.reader.list(**self.arguments)["items"][0]
        self.assertEqual(legacy["schema_version"], 0)
        self.assertIsNone(legacy["actor_user_id"])
        self.assertIsNone(legacy["event_id"])
        with self.connection.cursor() as sql:
            sql.execute("DROP TABLE cf_audit_event")
        with self.assertRaises(ContractError) as caught:
            self.reader.list(**self.arguments)
        self.assertEqual(caught.exception.status, 503)
        self.assertNotIn(self.database, caught.exception.message)

    def test_unbounded_queries_are_rejected(self):
        for change in ({"limit": True}, {"limit": 201}, {"end": "2027-01-01T00:00:00Z"},
                       {"start": self.arguments["end"]}, {"resource_uid": "not-a-uuid"}):
            with self.assertRaises(ContractError):
                self.reader.list(**{**self.arguments, **change})
