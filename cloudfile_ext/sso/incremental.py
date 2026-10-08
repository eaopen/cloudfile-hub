"""Small, bounded, authoritative EAP UID-scoped membership delta planner.

This pure module does not resolve identities, access Django, or mutate CE.
Direct CE memberships (not inherited department ancestors) are inputs.
"""


class IncrementalRefused(Exception):
    pass


def desired_external_groups(context):
    if not isinstance(context, dict) or context.get('status') not in ('active', 'disabled'):
        raise IncrementalRefused('invalid EAP user context')
    if not isinstance(context.get('organizations'), list) or not isinstance(context.get('roles'), list):
        raise IncrementalRefused('incomplete EAP group context')
    if context['status'] == 'disabled':
        return set()
    result = set()
    for org in context['organizations']:
        if (not isinstance(org, dict) or org.get('namespace') != 'directory'
                or not isinstance(org.get('external_id'), str) or not org['external_id']):
            raise IncrementalRefused('invalid EAP organization')
        result.add(org['external_id'])
    for role in context['roles']:
        if (not isinstance(role, dict) or role.get('namespace') != 'role'
                or not isinstance(role.get('external_id'), str) or not role['external_id']):
            raise IncrementalRefused('invalid EAP role')
        result.add('role:' + role['external_id'])
    return result


def plan_uid_delta(context, mapped, direct_group_ids, *, max_removals=0):
    """Return add/remove native group IDs for ONE fully checked EAP user.

    Do not infer EAP IDs from Seafile's native group integers. All EAP group
    identifiers are resolved via cf_sso_group_map first; an absent mapping
    prevents *any* mutation, including removal from an unrelated group.
    """
    desired = desired_external_groups(context)
    missing = desired - set(mapped)
    if missing:
        raise IncrementalRefused('full EAP group mapping must be ready first')
    mapped_ids = {v['group_id'] for v in mapped.values()}
    if len(mapped_ids) != len(mapped) or any(type(g) is not int or g <= 0 for g in mapped_ids):
        raise IncrementalRefused('invalid native group mapping')
    actual = set(direct_group_ids) & mapped_ids
    wanted = {mapped[eid]['group_id'] for eid in desired}
    add = sorted(wanted - actual)
    remove = sorted(actual - wanted)
    if type(max_removals) is not int or max_removals < 0:
        raise IncrementalRefused('invalid per-user removal guard')
    if len(remove) > max_removals:
        raise IncrementalRefused('UID delta exceeds permitted removals')
    return {'add': add, 'remove': remove}
