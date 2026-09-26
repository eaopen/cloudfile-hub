"""Request scope behavior with fixture contexts, not native lock evidence."""
import unittest
from unittest.mock import Mock

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.directory.preparation import SubjectPreparation


class SubjectReadScopeTests(unittest.TestCase):
    def setUp(self):
        self.preparation = SubjectPreparation.__new__(SubjectPreparation)
        self.preparation.actor = "employee-1"
        self.preparation._read_epoch = None
        self.preparation.contexts = Mock()
        self.current = dict(context_epoch="a" * 32)
        self.preparation.contexts.current.return_value = self.current

    def test_nested_reads_never_refresh_or_extend_ttl(self):
        with self.preparation.no_refresh_scope():
            with self.preparation.no_refresh_scope():
                self.assertEqual(self.preparation.prepare("employee-1"), self.current)
        self.preparation.contexts.get.assert_not_called()
        self.assertIsNone(self.preparation._read_epoch)
        self.preparation.prepare("employee-1")
        self.preparation.contexts.get.assert_called_once_with("employee-1", trigger="request")

    def test_expiry_or_epoch_change_discards_response_and_clears_scope(self):
        for current in (None, dict(context_epoch="b" * 32)):
            self.preparation.contexts.current.return_value = self.current
            with self.assertRaises(ContractError):
                with self.preparation.no_refresh_scope():
                    self.preparation.contexts.current.return_value = current
            self.assertIsNone(self.preparation._read_epoch)
        self.preparation.contexts.get.assert_not_called()

    def test_refresh_triggers_are_rejected_inside_scope(self):
        with self.preparation.no_refresh_scope():
            with self.assertRaises(ContractError):
                self.preparation.prepare("employee-1", trigger="login")
            with self.assertRaises(ContractError):
                self.preparation.refresh_for_management("employee-1")
