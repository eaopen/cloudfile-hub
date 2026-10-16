"""V2 directory ACL semantics only: no HTTP routes or file-byte authorization.

Seafile Pro reference: personal folder rule before group rules; sub-folder
rule overrides its parent within the same principal track. All actual
subjects must come from trusted native UID + current mapped GroupUser state.
This module does NOT activate cf_dir_acl; Server/Go must guard final commits.
"""
from dataclasses import dataclass

PERMISSIONS = frozenset(('r', 'rw', 'none', 'invisible'))
# Conservative merge of multiple matches of the same subject type and depth.
STRICTNESS = {'invisible': 0, 'none': 1, 'r': 2, 'rw': 3}
TYPES = ('user', 'org', 'role')


class PolicyError(ValueError):
    """Invalid ACL or missing trusted context: caller must fail closed."""


def canonical_path(value):
    if (not isinstance(value, str) or not value.startswith('/') or
            len(value.encode('utf-8')) > 4096 or '\\' in value or
            any(ord(c) < 32 or ord(c) == 127 for c in value) or
            (len(value) > 1 and value.endswith('/')) or '//' in value or
            any(part in ('.', '..') for part in value.split('/'))):
        raise PolicyError('invalid canonical ACL path')
    return value


def ancestors(path):
    canonical_path(path)
    if path == '/':
        return ('/',)
    parts = path.strip('/').split('/')
    return ('/',) + tuple('/' + '/'.join(parts[:i]) for i in range(1, len(parts) + 1))


def within(path, root):
    return root == '/' or path == root or path.startswith(root + '/')


@dataclass(frozen=True)
class Rule:
    repo_id: str
    path: str
    provider: str
    subject_type: str
    namespace: str
    external_id: str
    permission: str
    inherit: bool = True
    share_mode: bool = False

    def __post_init__(self):
        canonical_path(self.path)
        if (self.subject_type not in TYPES or self.permission not in PERMISSIONS or
                type(self.inherit) is not bool or type(self.share_mode) is not bool or
                any(not isinstance(s, str) or not s or s != s.strip()
                    for s in (self.repo_id, self.provider, self.namespace, self.external_id)) or
                (self.share_mode and (self.path == '/' or self.permission not in ('r', 'rw')))):
            raise PolicyError('invalid V2 directory ACL row')


@dataclass(frozen=True)
class Principal:
    provider: str
    uid: str
    # Only after verified GroupUser TTL / cf_sso_group_map lookup:
    # (subject_type, namespace, external_id) tuples, NEVER client claims.
    groups: frozenset = frozenset()
    active: bool = True
    ready: bool = True

    def matches(self, rule):
        if rule.provider != self.provider:
            return False
        if rule.subject_type == 'user':
            return rule.namespace == 'user' and rule.external_id == self.uid
        return (rule.subject_type, rule.namespace, rule.external_id) in self.groups


@dataclass(frozen=True)
class Decision:
    permission: str
    qualified_root: str | None
    from_rule: bool

    @property
    def can_read(self):
        return self.permission in ('r', 'rw')

    @property
    def can_write(self):
        return self.permission == 'rw'

    @property
    def visible(self):
        # 'none' may allow the name to be shown in an authorized parent list;
        # 'invisible' must hide the entry. Both deny file bytes.
        return self.permission != 'invisible'


def _track_permission(rules, principal, path, kind):
    winner = None
    for level in ancestors(path):
        candidates = [rule.permission for rule in rules
                      if rule.subject_type == kind and rule.path == level
                      and (level == path or rule.inherit)
                      and principal.matches(rule)]
        if candidates:
            # A deeper explicit rule replaces the ancestor rule in this track.
            # At the same path/type, any explicit deny wins; positive group
            # permissions merge like native Seafile (rw outranks r).
            denied = [p for p in candidates if p in ('invisible', 'none')]
            winner = (min(denied, key=STRICTNESS.__getitem__) if denied
                      else max(candidates, key=STRICTNESS.__getitem__))
    return winner


def _effective(rules, principal, path, base):
    # Pro personal-vs-group precedence applies across directory depths.
    for kind in TYPES:
        perm = _track_permission(rules, principal, path, kind)
        if perm is not None:
            return perm, True
    return base, False


def resolve(repo_id, path, principal, native_permission, rules, *, hard_readonly=False):
    """Evaluate canonical dir path; final callers still require C/Go enforcement.

    native_permission is current CE r/rw or None; admin is normalized to rw
    for content, not for Etech management authority. A non-library member only
    qualifies at a positive share_mode=1 directory root, never by an ACL row
    alone. Ancestor invisibility/denial prevents traversal. A separately shared
    subtree is a new navigation root and reveals no parent directories.
    """
    canonical_path(path)
    if (not isinstance(repo_id, str) or not repo_id or not isinstance(principal, Principal)
            or not principal.provider or not principal.uid or type(hard_readonly) is not bool
            or native_permission not in (None, 'r', 'rw')):
        raise PolicyError('invalid V2 ACL evaluation context')
    if not principal.active or not principal.ready:
        return Decision('invisible', None, False)
    if len(rules) > 4096:
        raise PolicyError('ACL candidate budget exceeded')
    selected = []
    unique = set()
    for rule in rules:
        if not isinstance(rule, Rule) or rule.repo_id != repo_id or rule.provider != principal.provider:
            raise PolicyError('mixed or malformed ACL candidate set')
        key = (rule.path, rule.provider, rule.subject_type, rule.namespace, rule.external_id)
        if key in unique:
            raise PolicyError('conflicting ACL rows')
        unique.add(key)
        if within(path, rule.path):
            selected.append(rule)
    if native_permission is not None:
        root, base = '/', native_permission
    else:
        # A direct share is not a parent-library qualification. Do not traverse
        # ancestors above its root or grant access to any sibling or library root.
        roots = [rule.path for rule in selected if rule.share_mode and principal.matches(rule)
                 and (rule.path == path or rule.inherit)]
        if not roots:
            return Decision('invisible', None, False)
        root = max(roots, key=len)
        base = 'none'
    for level in ancestors(path):
        if not within(level, root):
            continue
        perm, from_rule = _effective(selected, principal, level, base)
        if perm in ('none', 'invisible'):
            # Distinguish an explicitly blocked, visible node from a hidden
            # ancestor. A denied ancestor always hides its unreachable child.
            return Decision(perm if level == path else 'invisible', root, from_rule)
        if level == path:
            return Decision('r' if hard_readonly and perm == 'rw' else perm, root, from_rule)
    raise PolicyError('unreachable path evaluation')
