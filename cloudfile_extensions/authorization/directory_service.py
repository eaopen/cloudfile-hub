"""v0.9 policy service composed from one request-owned authenticated identity."""
from ..common.errors import invalid
from .directory_access import DirectoryAccessService
from .directory_management import DelegatedDirectoryManagement
from .scoped_read import ScopedContentReadAuthority
from .service import DirectoryPolicyService, safe_errors
from .share_service import DirectoryShareService


class DirectoryService(DirectoryPolicyService):
    def __init__(self, management, *, lifecycle_reader):
        super().__init__(management)
        # The same trusted reader pins sharing created through the unified ACL API.
        management.rules.lifecycle_reader = lifecycle_reader
        args = (management.preparation, management.core)
        options = dict(request_id=management.rules.request_id,
            cloud_mode=management.native_qualification.cloud_mode)
        self.admins = DirectoryPolicyService(DelegatedDirectoryManagement(*args, **options, administrators=True))
        self.shares = DirectoryShareService(management, lifecycle_reader=lifecycle_reader)
        self.access = DirectoryAccessService(ScopedContentReadAuthority(*args, **options, lifecycle_reader=lifecycle_reader))

    @safe_errors
    def effective(self, request):
        from ..common.validation import object_fields
        object_fields(request, ('reference',))
        return self.access.authority.inspect_policy(request['reference'])

    @safe_errors
    def list(self, domain, request, *, limit=50, after=None):
        if domain == 'admins':
            return self.admins.list('acl', request, limit=limit, after=after)
        if domain == 'shares':
            result = self.shares.list(request, limit=limit, after=after)
        else:
            result = super().list(domain, request, limit=limit, after=after)
        return {**result, 'subject_provider': self.management.state.provider}

    @safe_errors
    def create(self, domain, request, *, idempotency_key):
        if domain == 'admins':
            return self.admins.create('acl', request, idempotency_key=idempotency_key)
        if domain == 'shares':
            return self.shares.create(request, idempotency_key=self._key(idempotency_key))
        return super().create(domain, request, idempotency_key=idempotency_key)

    @safe_errors
    def replace(self, domain, rule_id, request, *, if_match, idempotency_key):
        if domain == 'admins':
            return self.admins.replace('acl', rule_id, request, if_match=if_match, idempotency_key=idempotency_key)
        if domain == 'shares':
            raise invalid('Update permissions and sharing mode through the ACL endpoint')
        return super().replace(domain, rule_id, request, if_match=if_match, idempotency_key=idempotency_key)

    @safe_errors
    def delete(self, domain, rule_id, request, *, if_match, idempotency_key):
        if domain == 'admins':
            return self.admins.delete('acl', rule_id, request, if_match=if_match, idempotency_key=idempotency_key)
        if domain == 'shares':
            return self.shares.delete(self._id(rule_id), request, if_match=self._condition(if_match),
                idempotency_key=self._key(idempotency_key))
        return super().delete(domain, rule_id, request, if_match=if_match, idempotency_key=idempotency_key)

    @safe_errors
    def resolve_directory(self, request):
        return self.access.resolve(request)

    @safe_errors
    def shared_with_me(self, *, limit=50, after=None):
        return self.access.shared_with_me(limit=limit, after=after)

    @safe_errors
    def directory_entries(self, request, *, limit=50, after=None):
        from .directory_entries import DirectoryEntriesService
        return DirectoryEntriesService(self.access.authority).list(request, limit=limit, after=after)

    @safe_errors
    def list_scope(self, request, *, limit=50, after=None):
        from .directory_scope import DirectoryScopeService
        return DirectoryScopeService(self.management, lifecycle_reader=self.shares.store.lifecycle_reader).list_scope(
            request, limit=limit, after=after)

    @safe_errors
    def revoke_scope(self, request, *, idempotency_key):
        from .directory_scope import DirectoryScopeService
        return DirectoryScopeService(self.management, lifecycle_reader=self.shares.store.lifecycle_reader).revoke(
            request, idempotency_key=idempotency_key)
