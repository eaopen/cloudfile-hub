"""Disposable MariaDB checks for CF-EDIT expiry and five-table drift.

The real native Branch publication remains a separate executable MVP gate.
This test requires the Server feature SQL to be checked out next to Hub.
"""
import hashlib
import os
from pathlib import Path
from unittest import TestCase
from uuid import uuid4

import pymysql

from cloudfile_ext.v2.editing_contract import (
    CommitRequest, EditConflict, Principal, reference,
)
from cloudfile_ext.v2.editing_store import EditingStore
from cloudfile_ext.v2.schema import FreshSchema, SchemaError


REPO = "11111111-1111-4111-8111-111111111111"
PATH = "/Engineering/part.step"
BASE = "a" * 40
STAGED = "b" * 40
ACTOR = Principal("uid-test", "u@auth.local", "integration", "plm-tool")


def sql_statements(file):
    body = Path(file).read_text()
    body = "\n".join(line for line in body.splitlines()
                     if not line.lstrip().startswith("--"))
    return [fragment.strip() for fragment in body.split(";") if fragment.strip()]


class CFEditMariaDBTests(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.conn = pymysql.connect(
            host=os.environ.get("CF_EDIT_MYSQL_HOST", "127.0.0.1"),
            port=int(os.environ.get("CF_EDIT_MYSQL_PORT", "3306")),
            user=os.environ.get("CF_EDIT_MYSQL_USER", "root"),
            password=os.environ.get("CF_EDIT_MYSQL_PASSWORD", "test"),
            database=os.environ.get("CF_EDIT_MYSQL_DB", "seafile_db"),
            autocommit=True)
        server = Path(os.environ.get("CF_EDIT_SERVER_TREE", "cloudfile-server"))
        cls.core = (server / "scripts/sql/mysql/cloudfile-v2.sql").read_text()
        cls.edit = (server / "scripts/sql/mysql/cloudfile-v2-edit.sql").read_text()
        with cls.conn.cursor() as cur:
            cur.execute("CREATE TABLE Branch (name VARCHAR(10), repo_id CHAR(36), "
                        "commit_id CHAR(40), PRIMARY KEY(name,repo_id)) ENGINE=InnoDB")
            for script in ("cloudfile-v2.sql", "cloudfile-v2-edit.sql"):
                for statement in sql_statements(server / "scripts/sql/mysql" / script):
                    cur.execute(statement)
            cur.execute("INSERT INTO Branch VALUES('master',%s,%s)", (REPO, BASE))
        cls.store = EditingStore(lambda repo_id, path, head: BASE)

    @classmethod
    def tearDownClass(cls):
        try:
            with cls.conn.cursor() as cur:
                for table in ("cf_commit_intent", "cf_edit_guard",
                              "cf_dir_acl", "cf_sso_group_map",
                              "cf_library_storage", "Branch"):
                    cur.execute("DROP TABLE IF EXISTS " + table)
        finally:
            cls.conn.close()

    def setUp(self):
        with self.conn.cursor() as cur:
            cur.execute("DELETE FROM cf_commit_intent")
            cur.execute("DELETE FROM cf_edit_guard")

    def reserve_prepared(self):
        self.conn.begin()
        with self.conn.cursor() as cur:
            proof = self.store.acquire(cur, repo_id=REPO, path=PATH,
                principal=ACTOR, expected_file_id=BASE, policy="renewable")
            intent = CommitRequest(str(uuid4()), "commit", BASE, STAGED, "f"*64)
            receipt = self.store.prepare(cur, repo_id=REPO, path=PATH,
                principal=ACTOR, request=intent, proof=proof)
            self.assertEqual(receipt["state"], "prepared")
        self.conn.commit()
        with self.conn.cursor() as cur:
            cur.execute("UPDATE cf_edit_guard SET lease_expires_at="
                        "TIMESTAMPADD(SECOND,-120,UTC_TIMESTAMP(6)) "
                        "WHERE repo_id=%s", (REPO,))
        return proof, intent

    def test_owner_can_cancel_expired_prepared_then_release(self):
        proof, intent = self.reserve_prepared()
        self.conn.begin()
        with self.conn.cursor() as cur:
            self.store.cancel_prepared(cur, repo_id=REPO, path=PATH,
                principal=ACTOR, intent_id=intent.intent_id, proof=proof)
            self.store.abandon(cur, repo_id=REPO, path=PATH,
                principal=ACTOR, proof=proof)
        self.conn.commit()
        with self.conn.cursor() as cur:
            cur.execute("SELECT state FROM cf_commit_intent WHERE intent_id=%s",
                        (intent.intent_id,))
            self.assertEqual(cur.fetchone()[0], "cancelled")
            cur.execute("SELECT guard_id,generation FROM cf_edit_guard "
                        "WHERE repo_id=%s", (REPO,))
            self.assertEqual(cur.fetchone(), (None, 1))
        # A prior token can never become the new user's credential.
        self.conn.begin()
        with self.conn.cursor() as cur:
            newer = self.store.acquire(cur, repo_id=REPO, path=PATH,
                principal=ACTOR, expected_file_id=BASE)
        self.conn.commit()
        self.assertEqual(newer.generation, 2)
        self.assertNotEqual(newer.guard_id, proof.guard_id)

    def test_manager_can_recover_expired_pending(self):
        proof, intent = self.reserve_prepared()
        mgr = Principal("admin", "admin@auth.local", "web", "admin-console")
        self.conn.begin()
        with self.conn.cursor() as cur:
            self.store.abandon(cur, repo_id=REPO, path=PATH, principal=mgr,
                               management=True, reason="approved recovery")
        self.conn.commit()
        with self.conn.cursor() as cur:
            cur.execute("SELECT state FROM cf_commit_intent WHERE intent_id=%s",
                        (intent.intent_id,))
            self.assertEqual(cur.fetchone()[0], "cancelled")
            cur.execute("SELECT guard_id FROM cf_edit_guard WHERE repo_id=%s",
                        (REPO,))
            self.assertIsNone(cur.fetchone()[0])

    def test_published_intent_cannot_be_cancelled_or_released(self):
        proof, intent = self.reserve_prepared()
        with self.conn.cursor() as cur:
            cur.execute("UPDATE cf_commit_intent SET state='published',"
                        "result_file_id=%s,result_commit_id=%s WHERE intent_id=%s",
                        (STAGED, "c"*40, intent.intent_id))
        self.conn.begin()
        with self.conn.cursor() as cur:
            with self.assertRaises(EditConflict):
                self.store.abandon(cur, repo_id=REPO, path=PATH,
                                   principal=ACTOR, proof=proof)
        self.conn.rollback()
        with self.conn.cursor() as cur:
            cur.execute("SELECT state FROM cf_commit_intent WHERE intent_id=%s",
                        (intent.intent_id,))
            self.assertEqual(cur.fetchone()[0], "published")
            cur.execute("SELECT guard_id FROM cf_edit_guard WHERE repo_id=%s",
                        (REPO,))
            self.assertEqual(cur.fetchone()[0], proof.guard_id)

    def test_five_table_schema_detects_missing_intent_receipt(self):
        schema = FreshSchema(self.conn, self.core, edit_ddl=self.edit)
        schema.verify()
        with self.conn.cursor() as cur:
            cur.execute("ALTER TABLE cf_commit_intent DROP COLUMN result_commit_id")
        with self.assertRaises(SchemaError):
            schema.verify()
        # Restore isolated test database to not affect later tests.
        with self.conn.cursor() as cur:
            cur.execute("ALTER TABLE cf_commit_intent ADD COLUMN "
                        "result_commit_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NULL "
                        "AFTER result_file_id")
        schema.verify()
