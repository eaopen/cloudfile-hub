"""Small, trust-boundary helpers for enterprise Directory facts.

This is not another identity store or permission engine. A trusted adapter
returns current user context and an entity snapshot; CE native User/Profile,
Group and GroupUser remain the only projection targets. Authentication and
file ACL authorization are separate responsibilities.
"""
from datetime import datetime, timezone

from .errors import IdentityConflict, IdentityUnavailable
from .identity import text
from .memberships import validate_subject


def verified_user(value, uid, *, account_field='account'):
    """Return (display/login label, optional creation account) for active UID.

    Existing accounts are always reused by exact CE Profile.login_id. A
    missing account field does not authorize creating a new anonymous user.
    Etech uses account_field='employee_no' for its existing payload.
    """
    login, _ = validate_subject(value, uid)
    if value['status'] != 'active':
        raise IdentityUnavailable('Directory user disabled')
    attrs = value['attributes']
    if not isinstance(account_field, str) or not account_field:
        raise IdentityUnavailable('invalid Directory account mapping')
    account = attrs.get(account_field)
    if account is not None and not isinstance(account, str):
        raise IdentityUnavailable('invalid Directory account value')
    return login, account



def direct_memberships(value, uid):
    """Read only directly assigned Org/Role keys from one validated snapshot.

    `organization_ancestors` is validated by the common subject parser but
    excluded from direct membership. This helper has no GroupUser write path;
    #55/#63 own any authorization-depth changes.
    """
    validate_subject(value, uid)
    if value['status'] != 'active':
        raise IdentityUnavailable('Directory user disabled')
    return frozenset(
        (kind, item['namespace'], item['external_id'])
        for field, kind in (('organizations', 'org'), ('roles', 'role'))
        for item in value[field])



def validated_entities(snapshot, *, expected_namespaces=None, now=None):
    """Validate a bounded Org/Role catalog; return {(kind,ns,id): name}.

    Parent IDs are accepted as trusted *facts* but deliberately do not change
    CE GroupUser membership: orgLevel/ancestor authorization belongs to #55.
    A consuming Etech adapter can retain its existing namespace restrictions.
    """
    now = datetime.now(timezone.utc) if now is None else now
    try:
        if (not isinstance(snapshot, dict) or snapshot['contract_version'] != '2.0'
                or snapshot['view'] != 'entities'):
            raise ValueError()
        generated = datetime.fromisoformat(snapshot['generated_at'].replace('Z', '+00:00'))
        if generated.tzinfo is None or not -60 <= (now - generated).total_seconds() <= 60:
            raise ValueError()
        groups = snapshot['groups']
        if not isinstance(groups, list) or len(groups) > 16384:
            raise ValueError()
        result = {}
        for item in groups:
            if not isinstance(item, dict):
                raise ValueError()
            kind = item['subject_type']
            if kind not in ('org', 'role'):
                raise ValueError()
            namespace, external = text(item['namespace'], 128), text(item['external_id'])
            if expected_namespaces is not None and (kind, namespace) not in expected_namespaces:
                raise ValueError()
            parent = item.get('parent_external_id')
            if parent is not None:
                if kind != 'org' or text(parent) == external:
                    raise ValueError()
            key = (kind, namespace, external)
            if key in result:
                raise ValueError()
            result[key] = text(item['name'], 255)
        return result
    except (KeyError, TypeError, ValueError, AttributeError, IdentityConflict):
        raise IdentityUnavailable('invalid trusted Directory entities') from None
