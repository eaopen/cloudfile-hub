"""Sparse directory delegation, independent of content qualification."""
from ..common.errors import invalid
from ..resources.paths import is_descendant_or_equal
from .management import DirectoryManagement
from .rules import ACLRules, rule_value


def management_value(value):
    if not isinstance(value, dict) or value.get('permission') != 'manage':
        raise invalid('Directory administrator permission must be manage')
    checked = rule_value({**value, 'permission': 'r'})
    if checked['kind'] != 'dir' or checked['path'] == '/':
        raise invalid('Directory delegation requires a non-root directory')
    return {**checked, 'permission': 'manage'}


def subject_keys(subject, provider):
    keys = {('user', provider, 'user', subject['userId'])}
    for kind, field in (('dept', 'organizations'), ('dept', 'organization_ancestors'), ('group', 'roles')):
        keys.update((kind, provider, item['namespace'], item['external_id']) for item in subject.get(field, []))
    return keys


class DirectoryAdminRules(ACLRules):
    TABLE = 'cf_dir_admin'
    ACTION_PREFIX = 'directory_admin'
    validate = staticmethod(management_value)


class DelegatedDirectoryManagement(DirectoryManagement):
    def __init__(self, *args, administrators=False, **kwargs):
        super().__init__(*args, **kwargs)
        self.administrators = administrators
        self.covering_grants = []
        self.grants = DirectoryAdminRules(self.state.connection, provider=self.state.provider,
            actor=self.actor, request_id=self.rules.request_id, authorize=self.authorize,
            finalize=self.finalize, authorize_change=self.authorize_change)
        if administrators:
            self.rules = self.grants

    def authorize(self, cursor, actor, reference):
        self.covering_grants = []
        self.prepare_authorization(cursor, actor, reference)
        if not self.qualification_ready:
            return False
        if self.can_manage_library():
            return True
        keys = subject_keys(self.current_subject, self.state.provider)
        for rule in self.grants.candidates(reference, locking=True):
            s = rule['subject']
            if ((s['type'], s['provider'], s['namespace'], s['external_id']) in keys and
                    is_descendant_or_equal(reference['path'], rule['path']) and
                    (rule['inherit'] or rule['path'] == reference['path'])):
                self.covering_grants.append(rule)
        return bool(self.covering_grants)

    def covers(self, path, *, descendants=False, strictly_below=False):
        if self.can_manage_library():
            return True
        return any(is_descendant_or_equal(path, grant['path']) and
            (not strictly_below or path != grant['path']) and
            (grant['inherit'] or (not descendants and path == grant['path']))
            for grant in self.covering_grants)

    def authorize_change(self, cursor, actor, reference, previous, value):
        if actor != self.actor:
            return False
        descendants = any(item is not None and item.get('inherit') for item in (previous, value))
        return self.covers(reference['path'], descendants=descendants, strictly_below=self.administrators)

    def authorize_share(self, cursor, actor, reference):
        return self.authorize(cursor, actor, reference) and self.covers(reference['path'], descendants=True)
