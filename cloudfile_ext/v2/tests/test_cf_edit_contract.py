"""Pure-Python CF-EDIT contract and transaction-order regression tests.

No mock pass is represented as a real Seafile/MariaDB E2E test.
"""
import hashlib
from unittest import TestCase
from unittest.mock import Mock
from uuid import UUID

from cloudfile_ext.v2.editing_contract import (
    CommitRequest, EditConflict, EditDenied, GuardProof, Principal,
    reference, verify_proof,
)
from cloudfile_ext.v2.editing_store import EditingStore, GUARD_FIELDS, INTENT_FIELDS
from cloudfile_ext.v2.schema import EDIT_TABLES, TABLES, SchemaError, statements


REPO = "11111111-1111-4111-8111-111111111111"
PATH = "/Engineering/part.step"
BASE = "a" * 40
NEXT = "b" * 40
ACTOR = Principal("uid-42", "user42@auth.local", "integration", "plm-1")


def fresh_guard(**changes):
    defaults = dict(repo_id=REPO, path_hash=reference(REPO, PATH), path=PATH,
                    guard_id=None, generation=0, credential_epoch=0, mode=None,
                    owner_uid=None, owner_native_user=None, client_type=None,
                    client_id=None, checkout_policy=None, proof_digest=None,
                    base_file_id=None, pending_intent=None, lease_expires_at=None,
                    active=False)
    defaults.update(changes)
    return defaults


class Cursor:
    """Records the SQL ordering; not a replacement for an InnoDB test."""
    def __init__(self, guard=None, intent=None):
        self.guard = guard or fresh_guard()
        self.intent = intent
        self.commands = []
        self.row = None

    def execute(self, sql, args=()):
        self.commands.append(sql)
        if sql.startswith("SELECT commit_id FROM Branch"):
            self.row = (BASE,)
        elif sql.startswith("SELECT repo_id,path_hash,path,guard_id"):
            self.row = tuple(self.guard[x] for x in GUARD_FIELDS)
        elif sql.startswith("SELECT intent_id,repo_id,path_hash"):
            self.row = tuple(self.intent[x] for x in INTENT_FIELDS) if self.intent else None
        elif sql.startswith("INSERT INTO cf_commit_intent"):
            keys = ("intent_id", "repo_id", "path_hash", "path", "guard_id",
                    "generation", "credential_epoch", "actor_uid", "action",
                    "expected_file_id", "staged_file_id", "content_digest",
                    "request_digest")
            self.intent = dict(zip(keys, args))
            self.intent.update(state="prepared", result_file_id=None, result_commit_id=None)
        elif sql.startswith("UPDATE cf_edit_guard SET guard_id=%s"):
            self.guard.update(guard_id=args[0], generation=args[1],
                              credential_epoch=1, mode=args[2], owner_uid=args[3],
                              owner_native_user=args[4], client_type=args[5],
                              client_id=args[6], checkout_policy=args[8],
                              proof_digest=args[9], base_file_id=args[10],
                              active=True)
        elif sql.startswith("UPDATE cf_edit_guard SET guard_id=NULL"):
            self.guard.update(fresh_guard(generation=self.guard["generation"]))
        elif sql.startswith("UPDATE cf_edit_guard SET pending_intent=%s"):
            self.guard["pending_intent"] = args[0]
        elif sql.startswith("UPDATE cf_edit_guard SET pending_intent=NULL"):
            self.guard["pending_intent"] = None
        elif sql.startswith("UPDATE cf_commit_intent SET state='cancelled'"):
            self.intent["state"] = "cancelled"
        else:
            self.row = None

    def fetchone(self):
        return self.row


class ProtocolTests(TestCase):
    def test_validates_canonical_path_and_native_id(self):
        self.assertEqual(len(reference(REPO, PATH)), 32)
        for path in ("/", "/a/../b", "/a//b", "/a\\b", "/a/"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                reference(REPO, path)

    def test_rejects_untrusted_actor_client_and_invalid_intent(self):
        with self.assertRaises(ValueError):
            Principal("user", "user", "root-shell", "any")
        with self.assertRaises(ValueError):
            CommitRequest("not-a-uuid", "commit", BASE, NEXT, "0" * 64)
        with self.assertRaises(ValueError):
            CommitRequest(REPO, "checkin-unchanged", BASE, NEXT, "0" * 64)

    def test_replay_digest_covers_principal_guard_and_bytes(self):
        proof = GuardProof(REPO, 2, 1, "c" * 64)
        request = CommitRequest(REPO, "commit", BASE, NEXT, hashlib.sha256(b"x").hexdigest())
        a = request.request_digest(REPO, PATH, ACTOR, proof)
        b = request.request_digest(REPO, PATH, ACTOR, GuardProof(REPO, 2, 2, "c" * 64))
        self.assertNotEqual(a, b)
        self.assertNotEqual(a, request.request_digest(REPO, PATH, Principal("another", ACTOR.native_user,
                             ACTOR.client_type, ACTOR.client_id), proof))

    def test_replay_separates_optimistic_from_checkout(self):
        request = CommitRequest(REPO, "optimistic", BASE, NEXT, "0" * 64)
        self.assertEqual(len(request.request_digest(REPO, PATH, ACTOR, None)), 64)
        with self.assertRaises(ValueError):
            request.request_digest(REPO, PATH, ACTOR, GuardProof(REPO, 1, 1, "f" * 64))

    def test_stale_device_credential_is_rejected(self):
        proof = GuardProof(REPO, 1, 1, "c" * 64)
        guard = fresh_guard(guard_id=REPO, generation=1, credential_epoch=1,
                            proof_digest=proof.token_digest, owner_uid=ACTOR.uid,
                            owner_native_user=ACTOR.native_user,
                            client_type=ACTOR.client_type, client_id=ACTOR.client_id,
                            active=True)
        verify_proof(guard, ACTOR, proof)
        with self.assertRaises(EditDenied):
            verify_proof(guard, Principal(ACTOR.uid, ACTOR.native_user, "agent", "other"), proof)
        guard["active"] = False
        with self.assertRaises(EditConflict):
            verify_proof(guard, ACTOR, proof)


class TransactionTests(TestCase):
    def setUp(self):
        self.reader = Mock(return_value=BASE)
        self.store = EditingStore(self.reader)

    def test_acquire_uses_branch_then_guard_and_new_secret(self):
        cursor = Cursor()
        proof = self.store.acquire(cursor, repo_id=REPO, path=PATH, principal=ACTOR,
                                   expected_file_id=BASE, policy="persistent")
        self.assertEqual(proof.generation, 1)
        self.assertEqual(len(proof.token), 64)
        self.assertEqual(cursor.guard["proof_digest"], proof.token_digest)
        sql = "\n".join(cursor.commands)
        self.assertLess(sql.index("SELECT commit_id FROM Branch"), sql.index("INSERT INTO cf_edit_guard"))
        self.assertLess(sql.index("FROM cf_edit_guard WHERE repo_id"), sql.index("UPDATE cf_edit_guard SET guard_id"))

    def test_second_checkout_is_rejected(self):
        cursor = Cursor(fresh_guard(guard_id=REPO, active=True))
        with self.assertRaises(EditConflict):
            self.store.acquire(cursor, repo_id=REPO, path=PATH,
                               principal=ACTOR, expected_file_id=BASE)
        self.reader.assert_not_called()

    def test_prepare_optimistic_intent_once_and_read_back(self):
        cursor = Cursor()
        req = CommitRequest(REPO, "optimistic", BASE, NEXT, "0" * 64)
        first = self.store.prepare(cursor, repo_id=REPO, path=PATH,
                                   principal=ACTOR, request=req)
        self.assertEqual(first["state"], "prepared")
        self.assertEqual(first["request_digest"], req.request_digest(REPO, PATH, ACTOR, None))
        self.assertEqual(len([x for x in cursor.commands if x.startswith("INSERT INTO cf_commit_intent")]), 1)
        second = self.store.prepare(cursor, repo_id=REPO, path=PATH,
                                    principal=ACTOR, request=req)
        self.assertEqual(first, second)
        self.assertEqual(len([x for x in cursor.commands if x.startswith("INSERT INTO cf_commit_intent")]), 1)

    def test_reuse_intent_with_different_file_is_rejected(self):
        cursor = Cursor()
        req = CommitRequest(REPO, "optimistic", BASE, NEXT, "0" * 64)
        self.store.prepare(cursor, repo_id=REPO, path=PATH, principal=ACTOR, request=req)
        changed = CommitRequest(REPO, "optimistic", BASE, "c" * 40, "0" * 64)
        with self.assertRaises(EditConflict):
            self.store.prepare(cursor, repo_id=REPO, path=PATH, principal=ACTOR, request=changed)

    def test_cannot_abandon_during_pending_publish(self):
        proof = GuardProof(REPO, 1, 1, "f" * 64)
        guard = fresh_guard(guard_id=REPO, generation=1, credential_epoch=1,
                            mode="checkout", checkout_policy="persistent",
                            owner_uid=ACTOR.uid, owner_native_user=ACTOR.native_user,
                            client_type=ACTOR.client_type, client_id=ACTOR.client_id,
                            proof_digest=proof.token_digest, pending_intent=REPO, active=True)
        with self.assertRaises(EditConflict):
            self.store.abandon(Cursor(guard), repo_id=REPO, path=PATH,
                               principal=ACTOR, proof=proof)


class SchemaContractTests(TestCase):
    def test_feature_requires_both_tables_and_core_is_unchanged(self):
        self.assertEqual(len(TABLES), 3)
        self.assertEqual(EDIT_TABLES, {"cf_edit_guard", "cf_commit_intent"})
        ddl = "".join("CREATE TABLE %s (id INT) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;"
                      % name for name in EDIT_TABLES)
        self.assertEqual(set(statements(ddl, allowed=EDIT_TABLES)), EDIT_TABLES)
        with self.assertRaises(SchemaError):
            statements(ddl)  # standard V2 keeps exactly three tables
