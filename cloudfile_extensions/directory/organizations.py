"""Effective ancestor expansion over a trusted coherent directory tree.

No source fetching/cache, native projection, project schema or readiness grant.
"""
from dataclasses import dataclass

from ..common.errors import ContractError
from ..common.validation import identifier, object_fields


@dataclass(frozen=True)
class OrganizationNode:
    namespace: str
    external_id: str
    parent_namespace: object
    parent_external_id: object
    enabled: bool


def effective_organizations(direct, nodes):
    """Exclude disabled nodes; reject missing/cyclic chains, never guess parents.

    Callers must supply a coherent primary-source tree matched to their subject
    snapshot; source etags are not ordered versions. Display names are irrelevant.
    """
    def unavailable():
        return ContractError("DIRECTORY_TREE_UNAVAILABLE", "Organization hierarchy is unavailable", 503)
    if not isinstance(nodes, (list, tuple)) or len(nodes) > 50000:
        raise unavailable()
    if not isinstance(direct, list) or len(direct) > 4096:
        raise unavailable()
    indexed = {}
    for node in nodes:
        if type(node) is not OrganizationNode or type(node.enabled) is not bool:
            raise unavailable()
        key = (identifier(node.namespace), identifier(node.external_id))
        if (node.parent_namespace is None) != (node.parent_external_id is None):
            raise unavailable()
        if node.parent_namespace is not None:
            identifier(node.parent_namespace)
            identifier(node.parent_external_id)
        if key in indexed:
            raise unavailable()
        indexed[key] = node
    selected, seen_direct = {}, set()
    for item in direct:
        object_fields(item, ("namespace", "external_id", "is_primary"))
        key = (identifier(item["namespace"]), identifier(item["external_id"]))
        if type(item["is_primary"]) is not bool or key in seen_direct:
            raise unavailable()
        seen_direct.add(key)
        if key not in indexed:
            raise unavailable()
        chain, visited = [], set()
        current = key
        while current is not None:
            if current in visited or len(visited) >= 128 or current not in indexed:
                raise unavailable()
            visited.add(current)
            node = indexed[current]
            chain.append((current, node))
            current = None if node.parent_namespace is None else (node.parent_namespace, node.parent_external_id)
        # A disabled direct affiliation cannot create ancestor membership.
        if not indexed[key].enabled:
            continue
        for ancestor, node in chain:
            if node.enabled:
                selected.setdefault(ancestor, False)
        selected[key] = selected[key] or item["is_primary"]
        if len(selected) > 4096:
            raise unavailable()
    if sum(selected.values()) > 1:
        raise unavailable()
    return [dict(namespace=namespace, external_id=external_id, is_primary=primary)
            for (namespace, external_id), primary in sorted(selected.items())]
