"""v0.9 same-transaction directory reads; not a transfer ticket issuer.

Directory APIs and Web transfer preflights use this scoped authority. Native
consumers independently repeat current qualification at byte access/publication.
"""
from ..resources.paths import is_descendant_or_equal, normalize_path
from .read import ContentReadAuthority
from .shares import DirectoryShares


class ScopedContentReadAuthority(ContentReadAuthority):
    def __init__(self, preparation, core, *, request_id, cloud_mode, lifecycle_reader, browse_root=None):
        super().__init__(preparation, core, request_id=request_id, cloud_mode=cloud_mode)
        self.shares = DirectoryShares(lifecycle_reader=lifecycle_reader)
        self.browse_root = None if browse_root is None else normalize_path(browse_root, 'dir')

    def subjects(self):
        value = self.current_subject
        provider = self.state.provider
        result = [dict(type='user', provider=provider, namespace='user', external_id=value['userId'])]
        for type_, key in (('dept', 'organizations'), ('dept', 'organization_ancestors'), ('group', 'roles')):
            result.extend(dict(type=type_, provider=provider, namespace=item['namespace'], external_id=item['external_id'])
                for item in value.get(key, []))
        return result

    def scope_allowed(self, reference):
        return self.browse_root is None or is_descendant_or_equal(reference['path'], self.browse_root)

    def management_permission(self, cursor, reference):
        from .directory_management import DirectoryAdminRules, subject_keys
        if self.can_manage_library():
            return True
        if not self.qualification_ready:
            return False
        keys = subject_keys(self.current_subject, self.state.provider)
        grants = DirectoryAdminRules(self.state.connection, provider=self.state.provider,
            actor=self.actor, request_id=self.rules.request_id, authorize=lambda *args: False)
        return any(tuple(rule['subject'][key] for key in ('type', 'provider', 'namespace', 'external_id')) in keys and
            (rule['path'] == reference['path'] or rule['inherit'])
            for rule in grants.candidates(reference, locking=True))

    def authorize(self, cursor, actor, reference):
        native = self.prepare_authorization(cursor, actor, reference)
        # No-library eligibility must not be confused with early rejection of
        # an inactive account, missing library, identity mismatch or barrier.
        if not self.qualification_ready or not self.scope_allowed(reference):
            return False
        decision = self.core.evaluate_scoped(reference, provider=self.state.provider,
            subject=self.current_subject, rules=self.rules.candidates(reference, locking=True),
            ce_permission=native, directory_shares=self.shares.candidates(cursor, reference, self.subjects()),
            attribute_allowlist=self.preparation.contexts.allowlist, hard_readonly=self.hard_readonly)
        return self.decision_allowed(decision)


class ScopedContentWriteAuthority(ScopedContentReadAuthority):
    """Content write preflight, never management permission or native publication."""
    def decision_allowed(self, decision):
        super().decision_allowed(decision)
        return self.effective_access['write']


def native_scoped_authority(preparation, core, *, request_id, cloud_mode, write=False):
    """Use the deployment-owned lifecycle adapter; a request cannot replace it."""
    from django.conf import settings
    from ..common.errors import ContractError
    reader = getattr(settings, 'CLOUDFILE_RESOURCE_LIFECYCLE_READER', None)
    if not callable(reader):
        raise ContractError('POLICY_UNAVAILABLE', 'Native lifecycle adapter is unavailable', 503)
    cls = ScopedContentWriteAuthority if write else ScopedContentReadAuthority
    return cls(preparation, core, request_id=request_id, cloud_mode=cloud_mode, lifecycle_reader=reader)
