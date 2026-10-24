"""Small SQL-mock tests for existing A-mode ACL batch publication (#57).

Demonstrates key-scoped diff, optimistic CAS, native Branch locking and
rollback. These tests do NOT prove that request-declared "managed" keys
belong to the caller; A/B writer ownership is a separate unresolved gate.
"""
from contextlib import contextmanager, nullcontext
from copy import deepcopy
import unittest
from unittest.mock import patch

from cloudfile_ext.v2.acl_batch import fingerprint, key_of
from cloudfile_ext.v2.acl_policy import PolicyError, Rule, StoredACLError
from cloudfile_ext.v2.acl_store import ACLStore, RevisionConflict, path_digest

REPO = "00000000-0000-4000-8000-000000000001"


def rule(path, permission="r", provider="etech"):
    return Rule(REPO, path, provider, "user", "user", "uid-42", permission)


class Cursor:
    def __init__(self, db):
        self.db, self.rows, self.rowcount = db, (), 0

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def fetchall(self):
        return self.rows

    def execute(self, sql, args=()):
        self.rows, self.rowcount = (), 0
        if sql.startswith("SELECT commit_id FROM ") and "FOR UPDATE" in sql:
            self.rows = (("native-commit",),)
            return

        def matching_key(params):
            repo_id, digest, subject_type, provider, namespace, external = params
            for key, (item, _) in self.db.rules.items():
                if (item.repo_id == repo_id and path_digest(item.path) == digest
                        and item.subject_type == subject_type
                        and item.provider == provider
                        and item.namespace == namespace
                        and item.external_id == external):
                    return key
            return None

        if sql.startswith("INSERT INTO ") and "cf_dir_acl" in sql:
            repo_id, path, provider, typ, ns, external, permission, inherit, share, rev, _ = args
            item = Rule(repo_id, path, provider, typ, ns, external, permission,
                        bool(inherit), bool(share))
            key = (provider, key_of(item))
            if key in self.db.rules:
                raise RuntimeError("duplicate native ACL key")
            self.db.rules[key] = (item, rev)
            self.rowcount = 1
        elif sql.startswith("UPDATE ") and "cf_dir_acl" in sql:
            permission, inherit, share, revision, *keys = args
            key = matching_key(keys)
            if key is not None:
                item, _ = self.db.rules[key]
                self.db.rules[key] = (
                    Rule(item.repo_id, item.path, item.provider, item.subject_type,
                         item.namespace, item.external_id, permission,
                         bool(inherit), bool(share)), revision)
                self.rowcount = 1
        elif sql.startswith("DELETE FROM ") and "cf_dir_acl" in sql:
            key = matching_key(args)
            if key is not None:
                del self.db.rules[key]
                self.rowcount = 1
        else:
            raise AssertionError("unexpected mocked SQL: " + sql)

        if sql.startswith(("UPDATE ", "DELETE FROM ", "INSERT INTO ")):
            self.db.writes += 1
            if self.db.fail_write:
                # Mimics a failed affected-row assertion; outer atomic()
                # must restore the entire candidate batch.
                self.rowcount = 0


class FakeDB:
    def __init__(self, rows=()):
        self.rules = {(r.provider, key_of(r)): (r, rev) for r, rev in rows}
        self.writes = self.commits = 0
        self.fail_write = False

    def cursor(self):
        return Cursor(self)

    @contextmanager
    def atomic(self):
        before = deepcopy(self.rules)
        try:
            yield
        except Exception:
            self.rules = before
            raise
        else:
            self.commits += 1

    def snapshot(self, repo_id, provider, *, lock=False):
        return tuple((item, rev) for (p, _), (item, rev) in self.rules.items()
                     if p == provider and item.repo_id == repo_id)


class ACLPublisherScopeTests(unittest.TestCase):
    def new_store(self):
        own = rule("/Managed", "r")
        untouched = rule("/Manual", "invisible")
        other = rule("/Managed", "rw", provider="another")
        db = FakeDB(((own, "r1"), (untouched, "r2"), (other, "r3")))
        store = ACLStore(db, "seafile", db.atomic, changed=lambda _: setattr(
            db, "invalidations", getattr(db, "invalidations", 0) + 1))
        store.provider_snapshot = db.snapshot
        return store, db, own, untouched, other

    def publish(self, store, db, *, managed, desired, expected=None):
        if expected is None:
            expected = fingerprint(db.snapshot(REPO, "etech"))
        with patch.object(store, "transfer_fence", return_value=nullcontext()):
            return store.replace_owned(REPO, "etech", expected=expected,
                                       managed=managed, desired=desired)

    def test_only_listed_natural_keys_are_changed(self):
        store, db, own, manual, other = self.new_store()
        new = rule("/Managed", "rw")
        outcome = self.publish(store, db, managed=[key_of(own)], desired=[new])
        self.assertEqual((outcome["updated"], outcome["deleted"], outcome["unchanged"]),
                         (1, 0, 0))
        self.assertEqual(db.rules[("etech", key_of(own))][0], new)
        self.assertEqual(db.rules[("etech", key_of(manual))], (manual, "r2"))
        self.assertEqual(db.rules[("another", key_of(other))], (other, "r3"))
        self.assertEqual((db.commits, db.invalidations), (1, 1))

    def test_unlisted_desired_rule_is_rejected_before_sql(self):
        store, db, own, manual, _ = self.new_store()
        with self.assertRaises(PolicyError):
            self.publish(store, db, managed=[key_of(own)],
                         desired=[rule("/Manual", "rw")])
        self.assertEqual((db.writes, db.commits), (0, 0))
        self.assertEqual(db.rules[("etech", key_of(manual))][0], manual)

    def test_delete_only_explicitly_managed_key(self):
        store, db, own, manual, _ = self.new_store()
        outcome = self.publish(store, db, managed=[key_of(own)], desired=[])
        self.assertEqual(outcome["deleted"], 1)
        self.assertNotIn(("etech", key_of(own)), db.rules)
        self.assertIn(("etech", key_of(manual)), db.rules)

    def test_stale_cas_refuses_batch_without_writes(self):
        store, db, own, manual, _ = self.new_store()
        with self.assertRaises(RevisionConflict):
            self.publish(store, db, expected="0" * 64,
                         managed=[key_of(own)], desired=[rule("/Managed", "rw")])
        self.assertEqual((db.writes, db.commits), (0, 0))
        self.assertEqual(db.rules[("etech", key_of(own))], (own, "r1"))

    def test_retry_with_current_fingerprint_is_idempotent(self):
        store, db, own, _, _ = self.new_store()
        self.publish(store, db, managed=[key_of(own)],
                     desired=[rule("/Managed", "rw")])
        changed = db.writes
        second = self.publish(store, db, managed=[key_of(own)],
                              desired=[rule("/Managed", "rw")])
        self.assertEqual(second["unchanged"], 1)
        self.assertEqual(db.writes, changed)
        self.assertEqual(db.invalidations, 1)

    def test_mid_batch_write_conflict_rolls_back(self):
        store, db, own, _, _ = self.new_store()
        before = deepcopy(db.rules)
        db.fail_write = True
        with self.assertRaises(StoredACLError):
            self.publish(store, db, managed=[key_of(own)],
                         desired=[rule("/Managed", "rw")])
        self.assertEqual(db.rules, before)
        self.assertEqual(db.commits, 0)
        self.assertEqual(getattr(db, "invalidations", 0), 0)


if __name__ == "__main__":
    unittest.main()
