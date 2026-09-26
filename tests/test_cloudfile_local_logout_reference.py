"""Local reference matching orchestration; not real SQL/session proof."""
import unittest
from unittest.mock import Mock

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.identity.session_index import OIDCSessionIndex


class LocalLogoutReferenceTests(unittest.TestCase):
    def setUp(self):
        self.index = object.__new__(OIDCSessionIndex)
        self.index.scope_hash = "a" * 64
        self.index._transaction = Mock()
        self.index.forget = Mock()
        self.cursor = Mock()
        self.key = "b" * 32
        self.reference = dict(scope_hash="a" * 64, subject_hash="c" * 64,
            sid_hash=None, authenticated_at=123)

    def test_exact_reference_only(self):
        self.cursor.fetchall.return_value = [("c" * 64, None, 123)]
        self.index.forget_reference(self.cursor, self.key, self.reference)
        self.index.forget.assert_called_once_with(self.cursor, self.key)

    def test_missing_is_idempotent(self):
        self.cursor.fetchall.return_value = []
        self.index.forget_reference(self.cursor, self.key, self.reference)
        self.index.forget.assert_not_called()

    def test_changed_reference_never_deleted(self):
        self.cursor.fetchall.return_value = [("d" * 64, None, 123)]
        with self.assertRaises(ContractError):
            self.index.forget_reference(self.cursor, self.key, self.reference)
        self.index.forget.assert_not_called()

    def test_wrong_scope_rejected_before_query(self):
        self.reference["scope_hash"] = "d" * 64
        with self.assertRaises(ContractError):
            self.index.forget_reference(self.cursor, self.key, self.reference)
        self.cursor.execute.assert_not_called()
