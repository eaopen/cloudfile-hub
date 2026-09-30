import pymysql

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.resources.store import ResourceEvidence
from cloudfile_extensions.schema.runner import SchemaRunner
from cloudfile_extensions.search.native_guards import NativeSearchGuards
from cloudfile_extensions.tests.test_schema import DatabaseTestCase


class NativeSearchGuardSQLTest(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        SchemaRunner(self.connection).apply()
        self.repo, self.commit = '11111111-1111-4111-8111-111111111111', 'a' * 40
        with self.connection.cursor() as sql:
            sql.execute('CREATE TABLE Branch(repo_id CHAR(36) NOT NULL,name VARCHAR(20) NOT NULL,commit_id CHAR(40) NOT NULL,PRIMARY KEY(repo_id,name)) ENGINE=InnoDB')
            sql.execute("INSERT INTO Branch VALUES(%s,'master',%s)", (self.repo, self.commit))
            sql.execute('INSERT INTO cf_managed_library VALUES(%s,UTC_TIMESTAMP(6))', (self.repo,))
        self.guards = NativeSearchGuards(provider='etech', generation='g1', login_resources=None,
            lifecycle_reader=lambda *_: ResourceEvidence('fixture-birth'))

    def test_directory_and_lifecycle_share_the_actual_branch_transaction(self):
        second = pymysql.connect(**self.options, database=self.database)
        try:
            with second.cursor() as sql:
                sql.execute('SET SESSION innodb_lock_wait_timeout=1')
            with self.guards.repo_scope(self.connection, self.repo):
                self.connection.begin()
                try:
                    with self.guards.snapshot_scope(self.repo, self.commit):
                        with self.connection.cursor() as sql:
                            with self.guards.lifecycle_scope(sql, dict(repo_id=self.repo, path='/x', kind='file')) as evidence:
                                self.assertEqual(evidence.lifecycle_ref, 'fixture-birth')
                            with self.assertRaises(pymysql.err.OperationalError) as error:
                                with second.cursor() as other:
                                    other.execute("UPDATE Branch SET commit_id=%s WHERE repo_id=%s", ('b' * 40, self.repo))
                            self.assertEqual(error.exception.args[0], 1205)
                finally:
                    self.connection.rollback()
            with second.cursor() as sql:
                sql.execute("UPDATE Branch SET commit_id=%s WHERE repo_id=%s", ('b' * 40, self.repo))
        finally:
            second.close()

    def test_unowned_or_changed_snapshot_never_enumerates(self):
        with self.assertRaises(ValueError):
            with self.guards.snapshot_scope(self.repo, self.commit):
                pass
        with self.guards.repo_scope(self.connection, self.repo):
            self.connection.begin()
            try:
                with self.assertRaises(ContractError) as error:
                    with self.guards.snapshot_scope(self.repo, 'b' * 40):
                        pass
                self.assertEqual(error.exception.code, 'SEARCH_REBUILD_PENDING')
            finally:
                self.connection.rollback()
