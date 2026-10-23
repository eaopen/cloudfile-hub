"""Shared page deadline, statement-local SQL, and disposable-engine checks."""
import os
from pathlib import Path
import re
import subprocess
import sys
from unittest import TestCase, skipUnless
from unittest.mock import Mock, MagicMock, patch

from cloudfile_ext.v2.tag_query_budget import query_budget, TagQueryTimeout


class QueryBudgetTests(TestCase):
    def connection(self, mariadb):
        return MagicMock(vendor='mysql', mysql_is_mariadb=mariadb)

    def test_both_engines_use_remaining_shared_budget_without_session_set(self):
        for mariadb in (False, True):
            db = self.connection(mariadb)
            execute = Mock()
            with patch('cloudfile_ext.v2.tag_query_budget.time.monotonic', side_effect=[10, 10.18]):
                with query_budget(db, 10.25):
                    wrapper = db.execute_wrapper.call_args.args[0]
                    wrapper(execute, 'SELECT name FROM tags WHERE id=%s', [7], False, {})
                    wrapper(execute, 'SELECT name FROM legacy WHERE id=%s', [8], False, {})
            statements = [call.args[0] for call in execute.call_args_list]
            if mariadb:
                limits = [float(re.search(r'max_statement_time=([\d.]+)', sql)[1]) * 1000 for sql in statements]
            else:
                limits = [int(re.search(r'MAX_EXECUTION_TIME\((\d+)\)', sql)[1]) for sql in statements]
            self.assertEqual(limits[0], 250)
            self.assertTrue(60 <= limits[1] <= 71)
            self.assertEqual([call.args[1] for call in execute.call_args_list], [[7], [8]])
            self.assertTrue(all('SET SESSION' not in sql for sql in statements))

    def test_exhaustion_never_emits_zero_or_runs_another_statement(self):
        db, execute = self.connection(True), Mock()
        with patch('cloudfile_ext.v2.tag_query_budget.time.monotonic', return_value=20):
            with query_budget(db, 20):
                wrapper = db.execute_wrapper.call_args.args[0]
                with self.assertRaises(TagQueryTimeout):
                    wrapper(execute, 'SELECT 1', (), False, {})
        execute.assert_not_called()

    def test_unsupported_backend_or_non_select_never_runs_unbounded(self):
        with self.assertRaises(ValueError):
            with query_budget(Mock(vendor='sqlite'), 20):
                self.fail('unsupported backend must not enter')
        db, execute = self.connection(False), Mock()
        with query_budget(db, 20):
            wrapper = db.execute_wrapper.call_args.args[0]
            for sql, many in [('UPDATE tags SET id=1', False), ('SELECT 1', True)]:
                with self.assertRaises(ValueError):
                    wrapper(execute, sql, (), many, {})
        execute.assert_not_called()

    @skipUnless(os.environ.get('CF_TAG_BUDGET_DISPOSABLE') == '1', 'isolated MySQL/MariaDB required')
    def test_real_database_cancels_slow_second_select_without_session_leak(self):
        result = subprocess.run([sys.executable, str(Path(__file__).with_name('tag_query_budget_sql_check.py'))],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
