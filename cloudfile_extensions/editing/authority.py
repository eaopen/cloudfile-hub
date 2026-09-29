"""Lease recovery management; no content-write authority or administrator bypass."""
from ..authorization.read import ContentReadAuthority


class LockManagementAuthority(ContentReadAuthority):
    def scope_allowed(self, reference):
        return self.is_owner

    def library_status_allowed(self, status):
        return status == 0
