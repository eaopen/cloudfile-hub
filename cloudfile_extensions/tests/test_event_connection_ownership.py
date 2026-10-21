"""Driver protocol fixtures, not a live MySQLdb transaction proof."""
import unittest
from unittest.mock import Mock

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.events.outbox import Outbox


class EventConnectionOwnershipTests(unittest.TestCase):
    def connection(self, status):
        connection = Mock(server_status=status)
        connection.get_autocommit.return_value = True
        return connection

    def test_protocol_transaction_bit_rejects_without_mutation(self):
        connection = self.connection(3)
        with self.assertRaises(ContractError):
            Outbox(connection)._require_idle()
        connection.cursor.assert_not_called()
        connection.commit.assert_not_called()
        connection.rollback.assert_not_called()

    def test_missing_driver_attribute_uses_exact_savepoint_error(self):
        connection = self.connection(None)
        from unittest.mock import MagicMock
        cursor = MagicMock()
        connection.cursor.return_value = cursor
        sql = cursor.__enter__.return_value
        sql.execute.side_effect = [None, RuntimeError(1305, "fixture missing savepoint")]
        Outbox(connection)._require_idle()
        self.assertEqual(sql.execute.call_count, 2)
        commands = [call.args[0] for call in sql.execute.call_args_list]
        self.assertEqual(commands[0].split()[-1], commands[1].split()[-1])
        connection.begin.assert_not_called()
        connection.commit.assert_not_called()

    def test_successful_probe_or_unknown_failure_never_commits_foreign_work(self):
        from unittest.mock import MagicMock
        for failure in (None, RuntimeError(2006, "fixture lost connection")):
            connection = self.connection(None)
            cursor = MagicMock()
            connection.cursor.return_value = cursor
            cursor.__enter__.return_value.execute.side_effect = [None, failure]
            with self.assertRaises(ContractError):
                Outbox(connection)._require_idle()
            connection.commit.assert_not_called()
            connection.rollback.assert_not_called()
