"""Pure token and adapter fixtures; no native/event publication proof."""
from unittest import TestCase
from unittest.mock import Mock, patch

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.search.policy_version import SearchPolicyVersionReader, change_token


class PolicyVersionTest(TestCase):
    REPO = "11111111-1111-4111-8111-111111111111"

    def test_both_streams_and_repo_are_bound(self):
        initial = change_token(self.REPO, (7, 11))
        self.assertEqual(initial, change_token(self.REPO, (7, 11)))
        for repo, watermarks in ((self.REPO, (8, 11)), (self.REPO, (7, 12)),
                ("22222222-2222-4222-8222-222222222222", (7, 11))):
            self.assertNotEqual(initial, change_token(repo, watermarks))

    def test_invalid_watermarks_rejected(self):
        for row in (None, (True, 0), (-1, 0), (0, 2 ** 64), ("1", 0), (1,)):
            with self.assertRaises(ValueError):
                change_token(self.REPO, row)

    def test_single_statement_and_owned_cleanup(self):
        connection = Mock()
        connection.get_autocommit.return_value = True
        sql = Mock()
        connection.cursor.return_value.__enter__ = Mock(return_value=sql)
        connection.cursor.return_value.__exit__ = Mock(return_value=False)
        sql.fetchone.return_value = (7, 11)
        with patch("cloudfile_extensions.search.policy_version.SchemaRunner"):
            result = SearchPolicyVersionReader(lambda: connection)(self.REPO)
        self.assertEqual(result, change_token(self.REPO, (7, 11)))
        sql.execute.assert_called_once()
        connection.close.assert_called_once()

    def test_foreign_transaction_untouched(self):
        connection = Mock()
        connection.get_autocommit.return_value = False
        with self.assertRaises(ContractError):
            SearchPolicyVersionReader(lambda: connection)(self.REPO)
        connection.rollback.assert_not_called()
        connection.close.assert_not_called()


from cloudfile_extensions.tests.test_schema import DatabaseTestCase


class PolicyVersionSQLTest(DatabaseTestCase):
    def test_mariadb_watermark_expression_returns_exact_integer_tokens(self):
        import pymysql
        from cloudfile_extensions.schema.runner import SchemaRunner
        SchemaRunner(self.connection).apply()
        reader = SearchPolicyVersionReader(lambda: pymysql.connect(**self.options, database=self.database))
        self.assertEqual(reader(PolicyVersionTest.REPO), change_token(PolicyVersionTest.REPO, (0, 0)))
