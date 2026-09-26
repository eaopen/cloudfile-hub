"""Directory scope/storage coverage; execution deferred until feature completion.

SQL authorization is an explicit fixture, not delegated runtime qualification.
"""
from datetime import datetime, timezone
import unittest
from uuid import uuid4

from cloudfile_extensions.authorization.admins import DirectoryAdmins
from cloudfile_extensions.authorization.management import DirectoryManagement
from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.schema.runner import SchemaRunner
from cloudfile_extensions.tests.test_schema import DatabaseTestCase


class AdminScopeTest(unittest.TestCase):
    def setUp(self):
        self.repo = str(uuid4())
        self.value = dict(repo_id=self.repo, path="/parts", kind="dir", permission="manage",
            inherit=False, subject=dict(type="user", provider="directory", namespace="user", external_id="u1"))

    def ref(self, path):
        return dict(repo_id=self.repo, path=path, kind="dir")

    def test_exact_scope_cannot_amplify_inheritance_or_path(self):
        self.assertTrue(DirectoryAdmins.permits([self.value], self.ref("/parts")))
        self.assertFalse(DirectoryAdmins.permits([self.value], self.ref("/parts"), inherit=True))
        self.assertFalse(DirectoryAdmins.permits([self.value], self.ref("/parts/sub")))
        self.assertFalse(DirectoryAdmins.permits([self.value], self.ref("/")))

    def test_inherited_scope_boundary_and_foreign_repo(self):
        scope = {**self.value, "inherit": True}
        self.assertTrue(DirectoryAdmins.permits([scope], self.ref("/parts/sub"), inherit=True))
        self.assertFalse(DirectoryAdmins.permits([scope], self.ref("/parts2/sub")))
        self.assertFalse(DirectoryAdmins.permits([scope], {**self.ref("/parts"), "repo_id": str(uuid4())}))

    def test_runtime_checks_old_and_new_inherited_effects(self):
        # Only exercises the change-scope hook, not CE/runtime authorization.
        runtime = object.__new__(DirectoryManagement)
        runtime.actor = "u1"
        runtime.current_subject = {"userId": "u1"}
        runtime.is_owner = False
        runtime._scopes = lambda reference: [self.value]
        check = lambda old, new: runtime.authorize_change(None, "u1", self.ref("/parts"), old, new)
        exact = {"inherit": False}
        inherited = {"inherit": True}
        self.assertTrue(check(None, exact))
        self.assertFalse(check(None, inherited))
        self.assertFalse(check(inherited, exact))
        self.assertFalse(check(inherited, None))
        self.assertFalse(runtime.authorize_change(None, "other", self.ref("/parts"), None, exact))
        runtime._scopes = lambda reference: [{**self.value, "inherit": True}]
        self.assertTrue(check(inherited, None))
        runtime.current_subject = None
        self.assertFalse(check(None, exact))


class AdminStorageTest(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        SchemaRunner(self.connection).apply()
        self.repo = str(uuid4())
        self.admins = DirectoryAdmins(self.connection, provider="directory", actor="manager",
            request_id="admin-fixture", authorize=lambda *_: True)
        self.ref = dict(repo_id=self.repo, path="/parts", kind="dir")
        self.value = dict(path="/parts", kind="dir", permission="manage", inherit=True,
            subject=dict(type="dept", provider="directory", namespace="department", external_id="engineering"))
        self.subject = dict(userId="u1", status="active", attributes={}, roles=[],
            organizations=[dict(namespace="department", external_id="engineering", is_primary=True)],
            etag="fixture", generated_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))

    def test_independent_persistence_scope_match_and_condition_delete(self):
        grant = self.admins.mutate(self.ref, value=self.value)
        child = {**self.ref, "path": "/parts/sub"}
        self.assertEqual(self.admins.scopes(child, subject=self.subject), [grant])
        self.assertEqual(self.admins.scopes({**child, "path": "/parts2"}, subject=self.subject), [])
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM cf_dir_acl WHERE repo_id=%s", (self.repo,))
            self.assertEqual(cursor.fetchone()[0], 0)
        with self.assertRaises(ContractError) as caught:
            self.admins.mutate(self.ref, rule_id=grant["id"])
        self.assertEqual(caught.exception.status, 428)
        self.admins.mutate(self.ref, rule_id=grant["id"], if_match=grant["etag"])
        self.assertEqual(self.admins.scopes(child, subject=self.subject), [])

    def test_content_permissions_and_file_delegations_rejected(self):
        for value in ({**self.value, "permission": "rw"},
                      {**self.value, "kind": "file"}):
            with self.assertRaises(ContractError):
                self.admins.mutate(self.ref, value=value)
