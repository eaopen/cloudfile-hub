"""Real MariaDB immutable optimistic Intent and atomic receipt contract."""
from uuid import uuid4
from cloudfile_extensions.tests.test_schema import DatabaseTestCase
from cloudfile_extensions.schema.runner import SchemaRunner
from cloudfile_extensions.local_edit.optimistic_intent import OptimisticIntentStore
from cloudfile_extensions.common.errors import ContractError


class OptimisticIntentSQLTests(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        SchemaRunner(self.connection).apply()
        self.store=OptimisticIntentStore()
        self.intent=str(uuid4())
        self.session=str(uuid4())
        self.device=str(uuid4())
        self.repo=str(uuid4())
        self.base="a"*40
        self.value=dict(intent_id=self.intent, base_file_id=self.base,
                        content_digest="b"*64, snapshot_size=1234)

    def test_original_intent_is_immutable_and_receipt_persistent(self):
        self.connection.begin()
        try:
            with self.connection.cursor() as sql:
                a=self.store.prepare(sql,self.value,session=self.session,
                                     device=self.device,repo=self.repo)
                self.assertEqual(a["state"],"prepared")
                b=self.store.prepare(sql,self.value,session=self.session,
                                     device=self.device,repo=self.repo)
                self.assertEqual(b,a)
                try:
                    self.store.prepare(sql,dict(self.value,content_digest="f"*64),
                        session=self.session,device=self.device,repo=self.repo)
                except ContractError:
                    pass
                else:
                    self.fail("same Intent altered original content")
                sql.execute("UPDATE cf_optimistic_upload_intent SET state='published',"
                            "result_file_id=%s,result_commit_id=%s WHERE intent_id=%s",
                            ("c"*40,"d"*40,self.intent))
            self.connection.commit()
            self.connection.begin()
            with self.connection.cursor() as sql:
                row=self.store.receipt(sql,self.intent,session=self.session,
                                       device=self.device,repo=self.repo)
                self.assertEqual(row["state"],"published")
                self.assertEqual(row["result_file_id"],"c"*40)
                denied=self.store.receipt(sql,self.intent,session=str(uuid4()),
                                           device=self.device)
                self.assertEqual(denied["state"],"not-found")
        finally:
            self.connection.rollback()

    def test_transaction_rolls_back_receipt_with_branch_simulation(self):
        self.connection.begin()
        try:
            with self.connection.cursor() as sql:
                self.store.prepare(sql,self.value,session=self.session,
                    device=self.device,repo=self.repo)
            self.connection.commit()
            self.connection.begin()
            with self.connection.cursor() as sql:
                sql.execute("UPDATE cf_optimistic_upload_intent SET state='published',"
                    "result_file_id=%s,result_commit_id=%s WHERE intent_id=%s",
                    ("c"*40,"d"*40,self.intent))
            self.connection.rollback()
            self.connection.begin()
            with self.connection.cursor() as sql:
                result=self.store.receipt(sql,self.intent,session=self.session,
                    device=self.device,repo=self.repo)
                self.assertEqual(result["state"],"prepared")
                self.assertIsNone(result["result_file_id"])
        finally:
            self.connection.rollback()
