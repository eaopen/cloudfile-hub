"""Lease recovery management; no content-write authority or administrator bypass."""
from ..authorization.read import ContentReadAuthority
from ..authorization.admins import DirectoryAdmins


class LockManagementAuthority(ContentReadAuthority):
    def scope_allowed(self, reference):
        return self.is_owner or DirectoryAdmins.permits(self._scopes(reference), reference)

    def library_status_allowed(self, status):
        return status == 0
