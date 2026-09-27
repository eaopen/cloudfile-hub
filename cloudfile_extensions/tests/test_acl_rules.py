"""SQL persistence tests; manager authorization is an explicit fixture.

Execution is deferred until overall feature verification, per user request.
"""
from uuid import uuid4
from unittest.mock import Mock

from cloudfile_extensions.authorization.rules import ACLRules
from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.schema.runner import SchemaRunner
from cloudfile_extensions.tests.test_schema import DatabaseTestCase


class ACLRulesTest(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        SchemaRunner(self.connection).apply()
        self.repo = str(uuid4())
        self.authorize = Mock(return_value=True)
        self.rules = ACLRules(self.connection, provider="directory", actor="manager",
            request_id="acl-fixture", authorize=self.authorize)

    def ref(self, path="/parts", kind="dir"):
        return dict(repo_id=self.repo, path=path, kind=kind)

    def value(self, path="/parts", *, kind="dir", permission="r", inherit=True):
        return dict(path=path, kind=kind, permission=permission, inherit=inherit,
            subject=dict(type="dept", provider="directory", namespace="dept", external_id="engineering"))

    def test_create_replace_strong_condition_and_delete(self):
        one = self.rules.mutate(self.ref(), value=self.value())
        self.assertEqual(self.rules.candidates(self.ref("/parts/drawing")), [one])
        with self.assertRaises(ContractError) as caught:
            self.rules.mutate(self.ref(), value=self.value(permission="rw"), rule_id=one["id"])
        self.assertEqual(caught.exception.status, 428)
        two = self.rules.mutate(self.ref(), value=self.value(permission="rw"),
            rule_id=one["id"], if_match=one["etag"])
        self.assertNotEqual(two["revision"], one["revision"])
        with self.assertRaises(ContractError) as caught:
            self.rules.mutate(self.ref(), rule_id=one["id"], if_match=one["etag"])
        self.assertEqual(caught.exception.status, 412)
        self.rules.mutate(self.ref(), rule_id=two["id"], if_match=two["etag"])
        self.assertEqual(self.rules.candidates(self.ref()), [])
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM cf_managed_library WHERE repo_id=%s", (self.repo,))
            self.assertEqual(cursor.fetchone()[0], 1)
            cursor.execute("SELECT COUNT(*) FROM cf_audit_event WHERE repo_id=%s", (self.repo,))
            self.assertEqual(cursor.fetchone()[0], 3)

    def test_durable_replay_is_authorized_and_has_no_duplicate_event(self):
        one = self.rules.mutate(self.ref(), value=self.value(), idempotency_key="create")
        self.assertEqual(self.rules.mutate(self.ref(), value=self.value(), idempotency_key="create"), one)
        with self.assertRaises(ContractError) as caught:
            self.rules.mutate(self.ref(), value=self.value(permission="rw"), idempotency_key="create")
        self.assertEqual(caught.exception.status, 409)
        deleted = self.rules.mutate(self.ref(), rule_id=one["id"], if_match=one["etag"], idempotency_key="delete")
        self.assertEqual(self.rules.mutate(self.ref(), rule_id=one["id"], if_match=one["etag"], idempotency_key="delete"), deleted)
        self.authorize.return_value = False
        with self.assertRaises(ContractError) as caught:
            self.rules.mutate(self.ref(), value=self.value(), idempotency_key="create")
        self.assertEqual(caught.exception.status, 403)
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM cf_audit_event WHERE repo_id=%s", (self.repo,))
            self.assertEqual(cursor.fetchone()[0], 2)

    def test_denied_management_and_duplicate_do_not_write_events(self):
        self.authorize.return_value = False
        with self.assertRaises(ContractError):
            self.rules.mutate(self.ref(), value=self.value())
        self.assertEqual(self.rules.candidates(self.ref()), [])
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM cf_managed_library WHERE repo_id=%s", (self.repo,))
            self.assertEqual(cursor.fetchone()[0], 0)
        self.authorize.return_value = True
        self.rules.mutate(self.ref(), value=self.value())
        with self.assertRaises(ContractError) as caught:
            self.rules.mutate(self.ref(), value=self.value())
        self.assertEqual(caught.exception.status, 409)
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM cf_audit_event WHERE repo_id=%s", (self.repo,))
            self.assertEqual(cursor.fetchone()[0], 1)

    def test_ancestor_boundary_and_file_deny_validation(self):
        self.rules.mutate(self.ref(), value=self.value())
        self.assertEqual(self.rules.candidates(self.ref("/parts2/drawing")), [])
        with self.assertRaises(ContractError):
            self.rules.mutate(self.ref("/parts/a.prt", "file"),
                value=self.value("/parts/a.prt", kind="file", permission="rw", inherit=False))
        deny = self.rules.mutate(self.ref("/parts/a.prt", "file"),
            value=self.value("/parts/a.prt", kind="file", permission="none", inherit=False))
        self.assertEqual(len(self.rules.candidates(self.ref("/parts/a.prt", "file"))), 2)
        self.assertEqual(len(self.rules.candidates(self.ref("/parts/a.prt", "dir"))), 1)
        self.assertEqual(deny["permission"], "none")

    def test_target_pagination_reauthorizes_and_rejects_foreign_or_deleted_anchor(self):
        created = []
        for external in ("one", "two", "three"):
            value = self.value()
            value["subject"] = {**value["subject"], "external_id": external}
            created.append(self.rules.mutate(self.ref(), value=value))
        ordered = sorted(created, key=lambda item: item["id"])
        self.rules.mutate(self.ref("/parts/sub"), value=self.value("/parts/sub"))
        first = self.rules.list_target(self.ref(), limit=2)
        self.assertEqual(first["items"], ordered[:2])
        self.assertEqual(first["next_after"], ordered[1]["id"])
        second = self.rules.list_target(self.ref(), limit=2, after=first["next_after"])
        self.assertEqual(second, dict(items=ordered[2:], next_after=None))
        self.authorize.return_value = False
        with self.assertRaises(ContractError) as caught:
            self.rules.list_target(self.ref(), after=first["next_after"])
        self.assertEqual(caught.exception.status, 403)
        self.authorize.return_value = True
        with self.assertRaises(ContractError) as caught:
            self.rules.list_target(self.ref("/parts/sub"), after=first["next_after"])
        self.assertEqual(caught.exception.status, 410)
        self.rules.mutate(self.ref(), rule_id=ordered[1]["id"], if_match=ordered[1]["etag"])
        with self.assertRaises(ContractError) as caught:
            self.rules.list_target(self.ref(), after=first["next_after"])
        self.assertEqual(caught.exception.status, 410)
        for limit in (True, 0, 101):
            with self.assertRaises(ContractError):
                self.rules.list_target(self.ref(), limit=limit)
