import csv
import io
import unittest
from unittest.mock import Mock

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.events.export import AuditCSV, csv_cell
from cloudfile_extensions.events.query import AuditReader


class AuditExportTests(unittest.TestCase):
    def setUp(self):
        self.reader = Mock()
        event = dict.fromkeys(AuditReader.FIELDS)
        event.update(id=1, operator="private@example.invalid", source_path="=CMD()", schema_version=0)
        self.reader.list.return_value = {"items": [event], "next_cursor": None}
        self.authorize = Mock(return_value=True)
        def redact(actor, row):
            row["operator"] = "[redacted]"
            row["raw_token"] = "do-not-export"
            return row
        self.export = AuditCSV(self.reader, authorize_export=self.authorize, redact=redact)
        self.query = dict(actor="user-1", repo_id="repo-1", start="start", end="end")

    def test_csv_quotes_redacts_and_never_adds_unknown_columns(self):
        content = b"".join(self.export.generate(**self.query)).decode()
        rows = list(csv.reader(io.StringIO(content)))
        row = dict(zip(rows[0], rows[1]))
        self.assertEqual(row["operator"], "[redacted]")
        self.assertEqual(row["source_path"], "'=CMD()")
        self.assertNotIn("private@", content)
        self.assertNotIn("do-not-export", content)
        self.assertEqual(row["actor_user_id"], "")

    def test_formula_and_control_prefixes_are_safe_and_roundtrip(self):
        for value in ("=1", "+1", "-1", "@x", " \t=1", "\ufeff=1", "\ufeff \ufeff=1", "\r=1", "a\nb", "a\x00b"):
            self.assertTrue(csv_cell(value).startswith("'"))
        for value in ("ordinary", "中文", "a,b", 'a"b', ""):
            self.assertEqual(csv_cell(value), value)

    def test_revocation_before_first_page_produces_no_output(self):
        self.authorize.return_value = False
        with self.assertRaises(ContractError) as caught:
            next(self.export.generate(**self.query))
        self.assertEqual(caught.exception.status, 403)
        self.reader.list.assert_not_called()

    def test_each_page_reauthorizes_and_failure_cannot_finish_successfully(self):
        self.reader.list.return_value["next_cursor"] = "next"
        self.authorize.side_effect = [True, False]
        stream = self.export.generate(**self.query)
        next(stream)
        next(stream)
        with self.assertRaises(ContractError) as caught:
            next(stream)
        self.assertEqual(caught.exception.status, 403)
        self.reader.list.assert_called_once()

    def test_rows_bytes_pages_and_nonadvancing_cursor_are_bounded(self):
        self.reader.list.return_value["items"] *= 2
        self.export.max_rows = 1
        with self.assertRaises(ContractError) as caught:
            list(self.export.generate(**self.query))
        self.assertEqual(caught.exception.code, "EXPORT_LIMIT")
        self.export.max_rows, self.export.max_bytes = 100, 1
        with self.assertRaises(ContractError):
            next(self.export.generate(**self.query))
        self.export.max_bytes, self.export.max_pages = 10000, 2
        self.reader.list.return_value = {"items": [], "next_cursor": "same"}
        with self.assertRaises(ContractError) as caught:
            list(self.export.generate(**self.query))
        self.assertEqual(caught.exception.code, "AUDIT_UNAVAILABLE")
        self.export.max_pages = 1
        with self.assertRaises(ContractError) as caught:
            list(self.export.generate(**self.query))
        self.assertEqual(caught.exception.code, "EXPORT_LIMIT")

    def test_redaction_failure_and_resume_request_rejected(self):
        self.export.redact = lambda *args: None
        with self.assertRaises(ContractError):
            list(self.export.generate(**self.query))
        with self.assertRaises(ContractError):
            next(self.export.generate(**self.query, cursor="old"))

    def test_export_cannot_change_facts_or_infer_legacy_identity(self):
        for changes in ({"id": 2}, {"result": "invented"}, {"actor_user_id": "guessed"},
                        {"actor_kind": "user"}):
            self.export.redact = lambda actor, row: {**row, **changes}
            with self.assertRaises(ContractError) as caught:
                list(self.export.generate(**self.query))
            self.assertEqual(caught.exception.status, 503)

    def test_redaction_exception_does_not_expose_internal_details(self):
        def failing(actor, row):
            raise RuntimeError("private deployment details")
        self.export.redact = failing
        with self.assertRaises(ContractError) as caught:
            list(self.export.generate(**self.query))
        self.assertNotIn("private", caught.exception.message)
