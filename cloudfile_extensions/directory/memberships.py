"""Pure managed-membership planning; no native mutations or authorization grant.

Inputs must come from a coherent directory snapshot and trusted persisted group
ownership maps. Apply and read-back belong to the native fenced coordinator.
"""

from dataclasses import dataclass

from ..common.errors import ContractError
from ..common.validation import identifier, object_fields
from .protocol import validate_subject


@dataclass(frozen=True)
class MembershipPlan:
    add: tuple
    remove: tuple
    retain: tuple
    unmanaged: tuple


def _group_id(value):
    if type(value) is not int or not 1 <= value <= 2147483647:
        raise ContractError("PROJECTION_UNAVAILABLE", "Invalid native group mapping", 503)
    return value


def plan_memberships(subject, *, user_id, provider_id, mappings, current_groups,
                     attribute_allowlist):
    """Reconcile only this provider's registered groups, never manual groups.

    Organizations already contain the source's effective ancestors; no primary
    department priority, display-name matching or project-specific logic here.
    Missing desired mappings fail closed, rather than silently dropping roles.
    """
    identifier(provider_id)
    subject = validate_subject(subject, requested_user_id=user_id,
                               attribute_allowlist=attribute_allowlist)
    if not isinstance(mappings, (list, tuple)) or len(mappings) > 16384:
        raise ContractError("PROJECTION_UNAVAILABLE", "Invalid native group mapping", 503)
    if not isinstance(current_groups, (list, tuple)) or len(current_groups) > 16384:
        raise ContractError("PROJECTION_UNAVAILABLE", "Invalid native memberships", 503)
    current = {_group_id(value) for value in current_groups}
    if len(current) != len(current_groups):
        raise ContractError("PROJECTION_UNAVAILABLE", "Duplicate native memberships", 503)
    keyed, owners = {}, {}
    for mapping in mappings:
        object_fields(mapping, ("provider", "subject_type", "namespace", "external_id", "group_id"))
        if mapping["subject_type"] not in {"dept", "group"}:
            raise ContractError("PROJECTION_UNAVAILABLE", "Invalid native group mapping", 503)
        key = (identifier(mapping["provider"]), mapping["subject_type"],
               identifier(mapping["namespace"]), identifier(mapping["external_id"]))
        group_id = _group_id(mapping["group_id"])
        if key in keyed or group_id in owners:
            raise ContractError("PROJECTION_CONFLICT", "Conflicting native group ownership", 409)
        keyed[key] = group_id
        owners[group_id] = key
    owned = {group_id for group_id, key in owners.items() if key[0] == provider_id}
    desired = set()
    if subject["status"] == "active":
        for field, subject_type in (("organizations", "dept"), ("roles", "group")):
            for item in subject[field]:
                key = (provider_id, subject_type, item["namespace"], item["external_id"])
                if key not in keyed:
                    raise ContractError("PROJECTION_UNAVAILABLE", "Required native group mapping is missing", 503)
                desired.add(keyed[key])
    return MembershipPlan(tuple(sorted(desired - current)),
                          tuple(sorted((current & owned) - desired)),
                          tuple(sorted(current & desired)),
                          tuple(sorted(current - owned)))
