"""Pure organization depth rules, without modifying CE GroupUser or ACL.

Parent links are trusted Directory facts, not CE group hierarchy. Only a
single Provider-wide orgLevel may be projected into flat CE GroupUser; a
per-ACL-rule depth requires separate authorization logic and review.
"""
from .errors import IdentityConflict, IdentityUnavailable
from .identity import text

MAX_ENTITIES = 16384


def org_parent_map(entities):
    """Validate a complete bounded Org parent graph from a trusted catalog.

    Org keys are (namespace, external_id). All referenced parents must be
    present, active in the supplied catalog, and within the same namespace.
    Role entities have no Org inheritance. Reject cycles and incomplete data
    before any permission projection. Does not query or modify a database.
    """
    try:
        if not isinstance(entities, (list, tuple)) or len(entities) > MAX_ENTITIES:
            raise ValueError()
        parents = {}
        for item in entities:
            if not isinstance(item, dict):
                raise ValueError()
            kind = item['subject_type']
            if kind == 'role':
                if item.get('parent_external_id') is not None:
                    raise ValueError()
                continue
            if kind != 'org':
                raise ValueError()
            namespace = text(item['namespace'], 128)
            external_id = text(item['external_id'])
            key = (namespace, external_id)
            if key in parents:
                raise ValueError()
            raw_parent = item.get('parent_external_id')
            parent = None if raw_parent is None else (namespace, text(raw_parent))
            if parent == key:
                raise ValueError()
            parents[key] = parent
        for parent in parents.values():
            if parent is not None and parent not in parents:
                raise ValueError()
        completed = set()
        for key in parents:
            node = key
            chain = set()
            while node is not None and node not in completed:
                if node in chain:
                    raise ValueError()
                chain.add(node)
                node = parents[node]
            completed.update(chain)
        return parents
    except (KeyError, TypeError, ValueError, AttributeError, IdentityConflict):
        raise IdentityUnavailable('invalid trusted organization parent graph') from None


def scoped_memberships(direct, parents, *, org_level=1):
    """Select Org ancestors of the current user's *direct* assignments.

    orgLevel=1: direct Org only. 2: plus immediate parents.
    N>=2: up to N-1 parent links. 0: all ancestors.
    Roles remain direct only; no ACL inheritance is inferred.
    The returned flat GroupUser candidate set MUST NOT be used where different
    libraries or rules require different orgLevel values.
    """
    if type(org_level) is not int or not 0 <= org_level <= MAX_ENTITIES:
        raise IdentityUnavailable('invalid organization depth')
    if not isinstance(parents, dict) or len(parents) > MAX_ENTITIES:
        raise IdentityUnavailable('invalid organization parent map')
    try:
        selected = set()
        for kind, namespace, external_id in direct:
            namespace = text(namespace, 128)
            external_id = text(external_id)
            if kind == 'role':
                selected.add(('role', namespace, external_id))
                continue
            if kind != 'org':
                raise ValueError()
            node = (namespace, external_id)
            if node not in parents:
                raise ValueError()
            hops = 0
            while node is not None:
                selected.add(('org', node[0], node[1]))
                if org_level and hops + 1 >= org_level:
                    break
                node = parents[node]
                hops += 1
        return frozenset(selected)
    except (KeyError, TypeError, ValueError, AttributeError, IdentityConflict):
        raise IdentityUnavailable('invalid scoped organization membership') from None
