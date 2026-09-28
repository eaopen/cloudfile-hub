"""Scoped audit API regression checks without a running Seafile installation."""
import unittest
from unittest.mock import MagicMock, Mock, patch

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.events.authorized_query import AuthorizedAuditQuery
from cloudfile_extensions.events.query import AuditReader


REPO = "11111111-1111-4111-8111-111111111111"
WINDOW = dict(repo_id=REPO, start="2026-09-01T00:00:00Z", end="2026-09-02T00:00:00Z")


class AuditScopeTests(unittest.TestCase):
    def test_library_and_object_use_different_transactional_authorities(self):
        query = AuthorizedAuditQuery.__new__(AuthorizedAuditQuery)
        query.authority = Mock(actor="alice", epoch="epoch")
        query.management = Mock(actor="alice", epoch="epoch")
        query.management.authorize.return_value = True
        query.service = Mock()
        query.service.events.return_value = {"items": [], "next_cursor": None}

        def consume(authority):
            def run(reference, reader):
                return reader(Mock(), reference)
            authority.consume.side_effect = run
        consume(query.authority)
        consume(query.management)

        query.events(WINDOW, scope="library", event_class="operations")
        query.management.consume.assert_called_once()
        query.authority.consume.assert_not_called()
        query.management.consume.reset_mock()
        query.management.epoch = "epoch"

        query.events({**WINDOW, "path": "/docs"}, scope="object", resource_kind="dir",
                     event_class="access")
        query.authority.consume.assert_called_once()
        self.assertEqual(query.authority.consume.call_args.args[0]["path"], "/docs")
        self.assertEqual(query.service.events.call_args.kwargs["path_scope"], "tree")

        query.management.consume.side_effect = ContractError("ACCESS_DENIED", "Denied", 403)
        with self.assertRaises(ContractError) as denied:
            query.events(WINDOW, scope="library", event_class="access")
        self.assertEqual(denied.exception.status, 403)

    def test_directory_query_uses_segment_boundary_and_class_filter(self):
        connection = MagicMock()
        connection.get_autocommit.return_value = True
        cursor = connection.cursor.return_value.__enter__.return_value
        cursor.fetchall.return_value = []
        reader = AuditReader(connection, secret=b"test-only-audit-key-with-32-bytes!",
                             authorize=lambda actor, event: True)
        with patch.object(reader, "_storage"):
            result = reader.list(actor="alice", **WINDOW, path="/docs", path_scope="tree",
                                 event_class="access")
        self.assertEqual(result, {"items": [], "next_cursor": None})
        sql, values = cursor.execute.call_args.args
        self.assertIn("operation IN ('file.view','file.download')", sql)
        self.assertIn("SUBSTRING(source_path,CHAR_LENGTH(%s)+1,1)='/'", sql)
        self.assertEqual(values[-8:], ["/docs"] * 8)


if __name__ == "__main__":
    unittest.main()
