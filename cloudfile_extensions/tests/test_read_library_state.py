"""State-domain contracts only, not native DB/ACL integration evidence."""
import unittest
from contextlib import nullcontext
from unittest.mock import MagicMock, Mock, patch
from types import SimpleNamespace
from uuid import uuid4
from cloudfile_extensions.common.errors import ContractError

from cloudfile_extensions.authorization.management import DirectoryManagement
from cloudfile_extensions.authorization.read import (
    ContentReadAuthority, ContentMetadataWriteAuthority, LibraryWideManagementAuthority)


class ReadLibraryStateTests(unittest.TestCase):
    def test_readonly_library_can_be_read_but_not_managed_or_modified(self):
        read = object.__new__(ContentReadAuthority)
        self.assertTrue(read.library_status_allowed(0))
        self.assertTrue(read.library_status_allowed(1))
        for authority_type in (DirectoryManagement, ContentMetadataWriteAuthority, LibraryWideManagementAuthority):
            authority = object.__new__(authority_type)
            with self.subTest(authority=authority_type):
                self.assertTrue(authority.library_status_allowed(0))
                self.assertFalse(authority.library_status_allowed(1))

    def test_suspended_and_unknown_states_never_qualify(self):
        for authority_type in (ContentReadAuthority, DirectoryManagement,
                ContentMetadataWriteAuthority, LibraryWideManagementAuthority):
            authority = object.__new__(authority_type)
            for status in (-1, 2, 3, 99):
                with self.subTest(authority=authority_type, status=status):
                    self.assertFalse(authority.library_status_allowed(status))

    def test_read_decision_cannot_infer_write_when_core_disallows_it(self):
        authority = object.__new__(ContentReadAuthority)
        self.assertTrue(authority.decision_allowed(dict(visible=True, read=True, write=False)))
        self.assertEqual(authority.effective_access, dict(read=True, write=False))

    def test_diagnostic_reports_deny_without_allowing_metadata_read(self):
        ref = dict(repo_id=str(uuid4()), path='/private', kind='dir')
        authority = object.__new__(ContentReadAuthority)
        authority.actor = 'user-1'
        authority.preparation = Mock()
        authority.state = Mock(provider='etech')
        authority.state.connection.cursor.return_value.__enter__ = Mock(return_value=Mock())
        authority.state.connection.cursor.return_value.__exit__ = Mock(return_value=False)
        authority.finalize = Mock()
        def deny(*args):
            authority.native_permission = 'r'
            authority.is_owner = False
            return authority.decision_allowed(dict(visible=False, read=False, write=False))
        authority.authorize = Mock(side_effect=deny)
        reader = Mock()
        with patch('cloudfile_extensions.authorization.read.scope_locks', return_value=nullcontext()):
            self.assertEqual(authority.inspect_policy(ref), dict(native_permission='r',
                effective_permission='invisible', can_manage=False))
            with self.assertRaises(ContractError):
                authority.consume(ref, reader)
            reader.assert_not_called()
            authority.authorize.side_effect = lambda *args: False
            with self.assertRaises(ContractError):
                authority.inspect_policy(ref)

    def test_directory_page_reuses_qualification_and_queries_rules_per_50(self):
        authority = object.__new__(ContentReadAuthority)
        authority.actor = 'user-1'
        authority.preparation = Mock(contexts=SimpleNamespace(allowlist=frozenset()))
        authority.state = SimpleNamespace(provider='directory', connection=MagicMock())
        authority.rules = SimpleNamespace(candidates_many=Mock(
            side_effect=lambda group, **kwargs: [[] for _ in group]))
        authority.core = SimpleNamespace(evaluate=Mock(side_effect=lambda ref, **kwargs: dict(
            visible=True, read=True, write=ref['path'] == '/item-50')))
        authority.finalize = Mock()
        def qualify(cursor, actor, ref):
            authority.native_permission = 'r'
            authority.current_subject = dict(userId=actor)
            authority.hard_readonly = False
            authority.epoch = 'epoch'
            return True
        authority.authorize = Mock(side_effect=qualify)
        repo = str(uuid4())
        references = [dict(repo_id=repo, path=f'/item-{index}', kind='dir')
                      for index in range(101)]
        with patch('cloudfile_extensions.authorization.read.scope_locks', return_value=nullcontext()):
            permissions = authority.consume_many(references)
        self.assertEqual(len(permissions), 101)
        self.assertEqual(permissions[50], 'rw')
        self.assertTrue(all(value == 'r' for index, value in enumerate(permissions) if index != 50))
        self.assertEqual(authority.authorize.call_count, 3)
        self.assertEqual(authority.rules.candidates_many.call_count, 3)
        self.assertEqual([len(call.args[0]) for call in authority.rules.candidates_many.call_args_list],
                         [50, 50, 1])
        self.assertEqual(authority.state.connection.commit.call_count, 3)
