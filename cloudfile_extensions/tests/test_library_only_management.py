"""Legacy directory grants never confer policy/tag/lock management."""
import unittest
from unittest.mock import Mock

from cloudfile_extensions.authorization.management import DirectoryManagement
from cloudfile_extensions.authorization.read import LibraryWideManagementAuthority
from cloudfile_extensions.locks.authority import LockManagementAuthority


class LibraryOnlyManagementTests(unittest.TestCase):
    def test_old_directory_grants_are_not_consulted(self):
        reference = dict(repo_id="repo", path="/parts", kind="dir")
        for authority_type in (DirectoryManagement, LockManagementAuthority):
            authority = object.__new__(authority_type)
            authority.is_owner = False
            authority.admins = Mock()
            authority.admins.scopes.return_value = [dict(path="/", inherit=True)]
            self.assertFalse(authority.scope_allowed(reference))
            authority.admins.scopes.assert_not_called()
            authority.is_owner = True
            self.assertTrue(authority.scope_allowed(reference))

    def test_directory_grants_do_not_authorize_library_tags(self):
        authority = object.__new__(LibraryWideManagementAuthority)
        authority.is_owner = False
        authority._scopes = Mock(return_value=[dict(path="/", inherit=True)])
        root = dict(repo_id="repo", path="/", kind="dir")
        self.assertFalse(authority.scope_allowed(root))
        authority._scopes.assert_not_called()
        authority.is_owner = True
        self.assertTrue(authority.scope_allowed(root))
        self.assertFalse(authority.scope_allowed({**root, "path": "/parts"}))

    def test_only_library_authority_can_change_directory_rules(self):
        authority = object.__new__(DirectoryManagement)
        authority.actor = "owner"
        authority.is_owner = False
        self.assertFalse(authority.authorize_change(None, "owner", {}, None, {}))
        authority.is_owner = True
        self.assertTrue(authority.authorize_change(None, "owner", {}, None, {}))
        self.assertFalse(authority.authorize_change(None, "other", {}, None, {}))

    def test_library_owner_can_repair_deny_without_granting_content_read(self):
        from cloudfile_extensions.authorization.read import ContentReadAuthority
        denied = dict(visible=False, read=False, write=False)
        management = object.__new__(DirectoryManagement)
        management.is_owner = True
        self.assertTrue(management.decision_allowed(denied))
        content = object.__new__(ContentReadAuthority)
        content.is_owner = True
        self.assertFalse(content.decision_allowed(denied))
