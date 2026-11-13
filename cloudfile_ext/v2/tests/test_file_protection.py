"""Contract tests: fake metadata is not a substitute for native C/Go E2E."""
import contextlib
import hashlib
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch, MagicMock

from cloudfile_ext.v2 import file_protection as protection

REPO = '11111111-1111-4111-8111-111111111111'
FILE = '/design/original.prt'
FILE_ID = 'a' * 40
HEAD = 'b' * 40


class ProtectionContractTests(unittest.TestCase):
    def tearDown(self):
        protection.protected_repositories.cache_clear()

    def test_native_repository_scope_is_strict_and_default_off(self):
        with TemporaryDirectory() as directory:
            config = Path(directory) / 'seafile.conf'
            config.write_text('[cloudfile]\nprotection_repo_ids = \n')
            with patch.dict(os.environ, {'SEAFILE_CENTRAL_CONF_DIR': directory}):
                protection.protected_repositories.cache_clear()
                self.assertEqual(protection.protected_repositories(), frozenset())
                config.write_text('[cloudfile]\nprotection_repo_ids = ' + REPO + '\n')
                protection.protected_repositories.cache_clear()
                self.assertTrue(protection.selected(REPO))
                config.write_text('[cloudfile]\nprotection_repo_ids = bad-id\n')
                protection.protected_repositories.cache_clear()
                with self.assertRaises(protection.ProtectionUnavailable):
                    protection.protected_repositories()

    def test_status_does_not_reach_table_for_off_repo(self):
        with patch.object(protection, 'selected', return_value=False), \
             patch.object(protection.connection, 'cursor', side_effect=AssertionError('unexpected SQL')):
            self.assertEqual(protection.read_batch(REPO, [FILE]), {})

    def test_rejects_non_admin_protect_and_unprotect(self):
        ordinary = SimpleNamespace(username='editor', is_active=True, is_staff=False)
        for op in (True, False):
            with self.assertRaises(PermissionError):
                protection._state_change(ordinary, {'repo_id': REPO, 'path': FILE,
                                                    'expected_file_id': FILE_ID}, op)

    def test_read_batch_returns_only_exact_protected_paths(self):
        digest = hashlib.sha256(FILE.encode()).digest()
        cursor = MagicMock()
        cursor.fetchall.return_value = [(digest, FILE, FILE_ID)]
        cursor.__enter__.return_value = cursor
        with patch.object(protection, 'selected', return_value=True), \
             patch.object(protection, '_tables', return_value=('prot', 'audit', 'branch')), \
             patch.object(protection.connection, 'cursor', return_value=cursor):
            self.assertEqual(protection.read_batch(REPO, [FILE]), {FILE: FILE_ID})
            self.assertEqual(cursor.execute.call_count, 1)
            self.assertIn('path_hash IN', cursor.execute.call_args.args[0])

    def test_concurrent_head_change_cannot_mark_file_protected(self):
        admin = SimpleNamespace(username='admin', is_active=True, is_staff=True,
                                admin_permissions=SimpleNamespace(can_manage_library=lambda: True))
        cursor = MagicMock()
        cursor.fetchone.return_value = ('c' * 40,)
        cursor.__enter__.return_value = cursor
        with patch.object(protection, 'selected', return_value=True), \
             patch.object(protection, 'Authority') as authority, \
             patch.object(protection, '_regular_file', return_value=(FILE_ID, HEAD)), \
             patch.object(protection, '_tables', return_value=('prot', 'audit', 'branch')), \
             patch.object(protection.connection, 'cursor', return_value=cursor), \
             patch.object(protection.transaction, 'atomic', return_value=contextlib.nullcontext()):
            authority.return_value.effective.return_value.can_read = True
            response = protection._state_change(
                admin, {'repo_id': REPO, 'path': FILE, 'expected_file_id': FILE_ID}, True)
            self.assertEqual(response.status_code, 409)
            self.assertEqual(cursor.execute.call_count, 1)  # No INSERT/DELETE
