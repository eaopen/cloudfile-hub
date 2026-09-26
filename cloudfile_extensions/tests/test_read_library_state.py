"""State-domain contracts only, not native DB/ACL integration evidence."""
import unittest

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
