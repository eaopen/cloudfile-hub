"""Schema equality must ignore data counters while detecting real drift."""
import unittest
from unittest.mock import Mock
from cloudfile_ext.v2.schema import FreshSchema


class DefinitionTests(unittest.TestCase):
    def definition(self, text):
        cursor = Mock()
        cursor.fetchone.return_value = ('cf_audit_event', text)
        return FreshSchema._definition(cursor, 'cf_audit_event')

    def test_populated_auto_increment_is_not_schema_drift(self):
        base = 'CREATE TABLE `cf_audit_event` (`id` bigint NOT NULL AUTO_INCREMENT, PRIMARY KEY (`id`)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin'
        self.assertEqual(self.definition(base), self.definition(base.replace('ENGINE=InnoDB', 'ENGINE=InnoDB AUTO_INCREMENT=982')))
        self.assertNotEqual(self.definition(base), self.definition(base.replace('NOT NULL AUTO_INCREMENT', 'NOT NULL')))
        self.assertNotEqual(self.definition(base), self.definition(base.replace('utf8mb4_bin', 'utf8mb4_general_ci')))
