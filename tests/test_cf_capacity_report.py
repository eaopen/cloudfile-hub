"""Offline contract tests for V05-01 (no Django installation or live DB)."""
import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch


def stub(name, **attributes):
    module = types.ModuleType(name)
    module.__dict__.update(attributes)
    sys.modules[name] = module

class BaseCommand:
    pass

class CommandError(Exception):
    pass

stub("django")
stub("django.conf", settings=types.SimpleNamespace())
stub("django.core")
stub("django.core.management")
stub("django.core.management.base", BaseCommand=BaseCommand, CommandError=CommandError)
stub("django.db", connection=types.SimpleNamespace())
stub("seahub")
stub("seahub.utils")
stub("seahub.utils.db_api", SeafileDB=lambda: types.SimpleNamespace(db_name="seafile_db"))
path = Path(__file__).resolve().parents[1] / "cloudfile_ext/management/commands/cf_capacity_report.py"
spec = importlib.util.spec_from_file_location("cf_capacity_report_under_test", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FakeCursor:
    def __init__(self, count=3):
        self.count = count
        self.statements = []
        self.current = 0

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        pass

    def execute(self, sql, params=None):
        self.statements.append((sql, params))
        self.current += 1

    def fetchone(self):
        return (self.count,)

    def fetchall(self):
        if "cf_background_job" in self.statements[-1][0]:
            return [("queued", 2), ("running", 1)]
        return [("repo-a", 123, 4), ("repo-b", None, None)]


class ReportTest(unittest.TestCase):
    def test_readonly_and_unknown_counts(self):
        cursor = FakeCursor()
        report = module.collect(db_name="seafile_db", limit=2, offset=0,
                                cursor_factory=lambda: cursor)
        self.assertEqual(3, report["library_count"])
        self.assertEqual(123, report["libraries"][0]["logical_bytes"]["value"])
        self.assertEqual("unknown", report["libraries"][1]["file_count"]["status"])
        self.assertEqual("unsupported", report["metrics"]["search_index_backlog"]["status"])
        self.assertTrue(report["page"]["has_more"])
        self.assertEqual(3, len(cursor.statements))
        self.assertTrue(all(s.lstrip().startswith("SELECT") for s, _ in cursor.statements))
        self.assertEqual([2, 0], cursor.statements[1][1])
        self.assertEqual(2, report["metrics"]["background_job_backlog"]["queued"])

    def test_unsafe_database_and_limits_refused(self):
        for name in ("", "db`; DROP TABLE Repo;", "dbname.dot"):
            with self.assertRaises(ValueError):
                module.collect(db_name=name, limit=2, offset=0, cursor_factory=FakeCursor)
        for limit, offset in ((0, 0), (1001, 0), (1, -1)):
            with self.assertRaises(ValueError):
                module.collect(db_name="seafile_db", limit=limit, offset=offset,
                               cursor_factory=FakeCursor)

    def test_missing_disk_is_explicit(self):
        with patch.object(module.shutil, "disk_usage", side_effect=OSError("unavailable")):
            report = module.collect(db_name="seafile_db", limit=2, offset=0,
                                    disk_path="/missing", cursor_factory=FakeCursor)
        self.assertEqual("unknown", report["metrics"]["disk_available_bytes"]["status"])
        self.assertEqual(["disk usage unavailable"], report["errors"])


if __name__ == "__main__":
    unittest.main()
