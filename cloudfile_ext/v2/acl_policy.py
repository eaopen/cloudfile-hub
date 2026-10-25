"""V2 directory ACL semantics only: no HTTP routes or file-byte authorization.

Seafile Pro reference: personal folder rule before group rules; sub-folder
rule overrides its parent within the same principal track. All actual
subjects must come from trusted native UID + current mapped GroupUser state.
This module does NOT activate cf_dir_acl; Server/Go must guard final commits.
"""
from dataclasses import dataclass

PERMISSIONS = frozenset(('r', 'rw', 'invisible'))
# Conservative merge of multiple matches of the same subject type and depth.
STRICTNESS = {'invisible': 0, 'r': 1, 'rw': 2}
TYPES = ('user', 'org', 'role')


class PolicyError(ValueError):
    """Invalid ACL or missing trusted context: caller must fail closed."""


class StoredACLError(PolicyError):
    """A stored row contradicts its own path, hash, revision or schema shape.

    Kept apart from a caller mistake on purpose: it is still fail-closed, but it
    is our fault, not the requester's. Reporting it as a bad request blamed the
    caller and let one legacy encoding look like an ACL outage (DEV 2026-10-20).
    """


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
        # Only the explicit 'invisible' rule denies and hides a directory.
        # No configurable 'none' ACL exists in V2.
        return self.permission != 'invisible'


def narrow_to_native(decision, native):
    """What the native library gate leaves of a V2 decision; None means deny.

    The native grant is a *qualification*, not a ceiling: a library read may be
    raised to write by a matching directory rule (见
    docs/v2.0/directory-inheritance-deny-ce-pro-20261016.md「库 r 可经有效目录
    规则提升为 rw」). A library write is still narrowed by the rules, because
    the decision passed in already evaluated them on top of the native base.
    A directory share exists for users with no native library permission at
    all, so at a positive share root the absence of a native grant is the
    normal case and that root is the authorization. Every other path still
    requires a native grant: an absent ('none', None) or denied ('invisible')
    native permission keeps failing closed.
    """
    if native in ('r', 'rw'):
        return decision
    if native in (None, 'none') and decision.from_rule and decision.qualified_root not in (None, '/'):
        return decision
    return None


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
            denied = [p for p in candidates if p == 'invisible']
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
    for content, not for enterprise Directory management authority. A non-library member only
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
            raise StoredACLError('mixed or malformed ACL candidate set')
        key = (rule.path, rule.provider, rule.subject_type, rule.namespace, rule.external_id)
        if key in unique:
            raise StoredACLError('conflicting ACL rows')
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
            # 'none' is an internal lack-of-grant sentinel, never a stored rule.
            # A denied or unqualified ancestor always hides its unreachable child.
            return Decision('invisible', root, from_rule)
        if level == path:
            return Decision('r' if hard_readonly and perm == 'rw' else perm, root, from_rule)
    raise PolicyError('unreachable path evaluation')
