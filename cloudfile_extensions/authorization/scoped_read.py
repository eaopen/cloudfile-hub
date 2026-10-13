"""v0.9 same-transaction directory reads; not a transfer ticket issuer.

This explicit authority leaves the legacy CE route unchanged until native byte
and write consumers are connected to the same scoped qualification contract.
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

