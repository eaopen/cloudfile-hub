"""Read-only V2 inventory distinguishes the 001..042 legacy catalog from V2."""
import unittest
from unittest.mock import MagicMock

from cloudfile_ext.v2.schema import (
    TABLES, V2_FIELDS, V2_INDEXES, FreshSchema, classify_v2_table,
)


def layout(name):
    return dict(V2_FIELDS[name]), dict(V2_INDEXES[name])


class SchemaInventoryTests(unittest.TestCase):
    def test_current_core_and_optional_guard(self):
        for name in V2_FIELDS:
            with self.subTest(table=name):
                columns, indexes = layout(name)
                self.assertEqual(classify_v2_table(name, columns, indexes), 'current')

    def test_old_edit_guard_is_not_v2(self):
        columns, indexes = layout('cf_edit_guard')
        del columns['path']
        del columns['lease_expires_at']
        columns['resource_uid'] = ('char', 36)
        columns['lifecycle_ref'] = ('varchar', 512)
        columns['lease_until'] = ('datetime', None)
        self.assertEqual(classify_v2_table('cf_edit_guard', columns, indexes), 'legacy')

    def test_legacy_acl_and_group_map(self):
        fields, indexes = layout('cf_dir_acl')
        fields['path_hash'] = ('char', 64)
        fields['subject_hash'] = ('char', 64)
        self.assertEqual(classify_v2_table('cf_dir_acl', fields, indexes), 'legacy')
        fields, indexes = layout('cf_sso_group_map')
        fields['id'] = ('bigint', None)
        fields['group_id'] = ('int', None)
        self.assertEqual(classify_v2_table('cf_sso_group_map', fields, indexes), 'legacy')

    def test_missing_active_index_or_wrong_hash_is_not_current(self):
        fields, indexes = layout('cf_edit_guard')
        indexes.pop('cf_edit_guard_active')
        self.assertEqual(classify_v2_table('cf_edit_guard', fields, indexes), 'incompatible')
        fields, indexes = layout('cf_edit_guard')
        fields['path_hash'] = ('char', 64)
        self.assertEqual(classify_v2_table('cf_edit_guard', fields, indexes), 'incompatible')

    def test_inventory_is_select_only_and_lists_extra_tables(self):
        # Fake only information_schema: checking existing DBs must never run
        # legacy migrations, modify records or create temporary tables.
        tables = set(TABLES) | {'cf_edit_guard', 'cf_resource'}
        class Cursor:
            def __init__(self):
                self.result = []
                self.statements = []
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def execute(self, sql, args=()):
                self.statements.append(sql)
                if 'information_schema.tables' in sql:
                    self.result = [(name,) for name in sorted(tables)]
                elif 'information_schema.COLUMNS' in sql:
                    self.result = [(key, kind, length)
                                   for key, (kind, length) in V2_FIELDS[args[0]].items()]
                elif 'information_schema.STATISTICS' in sql:
                    self.result = [(key, field)
                                   for key, fields in sorted(V2_INDEXES[args[0]].items())
                                   for field in fields]
                else:
                    raise AssertionError('unexpected query: '+sql)
            def fetchall(self):
                return self.result
        cursor = Cursor()
        conn = MagicMock()
        conn.get_autocommit.return_value = True
        conn.cursor.return_value = cursor
        # Avoid passing fake DDL through the constructor; the inventory works
        # independent of the DDL parser once its stable metadata is loaded.
        obj = FreshSchema.__new__(FreshSchema)
        obj.connection = conn
        result = obj.inspect()
        self.assertEqual(result['status'], 'migration_review_required')
        self.assertEqual(result['tables']['cf_edit_guard'], 'current')
        self.assertEqual(result['unexpected_cf_tables'], ['cf_resource'])
        self.assertTrue(all('information_schema' in sql.lower()
                            for sql in cursor.statements))


if __name__ == '__main__':
    unittest.main()
