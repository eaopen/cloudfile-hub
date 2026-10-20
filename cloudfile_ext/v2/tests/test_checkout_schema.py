"""The optional edit detector must distinguish two real Guard DDL contracts."""
import importlib.util
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import MagicMock

SOURCE = Path(__file__).resolve().parents[1] / 'checkout_schema.py'
SPEC = importlib.util.spec_from_file_location('checkout_schema', SOURCE)
SCHEMA = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SCHEMA)


class CheckoutSchemaTests(TestCase):
    def detect(self, columns, indexes=None):
        connection = MagicMock()
        cursor = connection.cursor.return_value.__enter__.return_value
        if indexes is None:
            indexes = [(name, unique, i + 1, column, None)
                       for name, (unique, parts) in SCHEMA.PATH_INDEXES.items()
                       for i, column in enumerate(parts)]
        cursor.fetchall.side_effect = [[(name,) for name in columns], indexes]
        result = SCHEMA.path_checkout_available(connection, 'files')
        self.assertTrue(all(call.args[0].startswith('SELECT ') for call in cursor.execute.call_args_list))
        return result, cursor

    def test_missing_or_resource_store_does_not_enable_path_checkout(self):
        for columns in ([], SCHEMA.RESOURCE_COLUMNS):
            available, cursor = self.detect(columns)
            self.assertFalse(available)
            self.assertEqual(cursor.execute.call_count, 1)

    def test_complete_path_schema_enables_optional_checkout(self):
        available, cursor = self.detect(SCHEMA.PATH_COLUMNS)
        self.assertTrue(available)
        self.assertEqual(cursor.execute.call_count, 2)

    def test_missing_columns_or_mixed_contract_fail_explicitly(self):
        for columns in (SCHEMA.PATH_COLUMNS - {'lease_expires_at'},
                        SCHEMA.PATH_COLUMNS | {'resource_uid'}):
            with self.assertRaises(RuntimeError):
                self.detect(columns)

    def test_missing_wrong_or_partial_indexes_do_not_enable_checkout(self):
        base = [(name, unique, i + 1, column, None)
                for name, (unique, parts) in SCHEMA.PATH_INDEXES.items()
                for i, column in enumerate(parts)]
        cases = [[], [row for row in base if row[0] != 'cf_edit_guard_active'],
                 [row[:3] + ('wrong', row[4]) if row[0] == 'PRIMARY' else row for row in base],
                 [row[:4] + (8,) if row[0] == 'PRIMARY' else row for row in base]]
        for indexes in cases:
            with self.assertRaises(RuntimeError):
                self.detect(SCHEMA.PATH_COLUMNS, indexes)


if __name__ == '__main__':
    main()
