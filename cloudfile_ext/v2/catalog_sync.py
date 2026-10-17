"""One PowerJob-triggered, idempotent entity catalog reconciliation.

Only Etech organization/role entities are managed here. Users and GroupUser
memberships are intentionally untouched; they are refreshed by UID on demand.
"""
from datetime import datetime, timezone

from .directory_client import DirectoryClient, configuration
from .errors import IdentityUnavailable
from .identity import text
from .memberships import GroupCatalog


def validate_entities(snapshot):
    try:
        if (not isinstance(snapshot, dict) or snapshot.get('view') != 'entities'
                or snapshot.get('contract_version') != '2.0'
                or not isinstance(snapshot.get('revision'), str)
                or not snapshot['revision'].startswith('sha256:')
                or len(snapshot['revision']) != 71):
            raise ValueError()
        stamp = datetime.fromisoformat(snapshot['generated_at'].replace('Z', '+00:00'))
        if stamp.tzinfo is None or abs((datetime.now(timezone.utc) - stamp).total_seconds()) > 180:
            raise ValueError()
        rows = snapshot['groups']
        if not isinstance(rows, list) or not 0 < len(rows) <= 16384:
            raise ValueError()
        entities = {}
        for item in rows:
            if not isinstance(item, dict) or set(item) != {
                    'subject_type', 'namespace', 'external_id', 'name', 'parent_external_id'}:
                raise ValueError()
            kind, namespace = item['subject_type'], item['namespace']
            if (kind, namespace) not in (('org', 'directory'), ('role', 'role')):
                raise ValueError()
            key = (kind, namespace, text(item['external_id']))
            if key in entities:
                raise ValueError()
            text(item['name'], 255)
            parent = item['parent_external_id']
            if parent is not None:
                if kind != 'org':
                    raise ValueError()
                text(parent)
            entities[key] = item
        # Validate the complete hierarchy before the first native write.
        for key, item in entities.items():
            seen = {key[2]}
            parent = item['parent_external_id']
            while parent is not None:
                if parent in seen or ('org', 'directory', parent) not in entities:
                    raise ValueError()
                seen.add(parent)
                parent = entities[('org', 'directory', parent)]['parent_external_id']
        return [entities[key] for key in sorted(entities)]
    except (KeyError, ValueError, TypeError, AttributeError):
        raise IdentityUnavailable('invalid Directory entity catalog') from None


def reconcile(snapshot, *, catalog, native_lookup, rename):
    """Pure coordination atop the existing native GroupCatalog; fail closed.

    Missing entities are not automatically unmapped or deleted: their original
    CE groups may still own repositories and are reviewed separately.
    """
    rows = validate_entities(snapshot)
    created = renamed = unchanged = 0
    for item in rows:
        group = catalog.ensure(item['subject_type'], item['namespace'],
                               item['external_id'], item['name'])
        native = native_lookup(group)
        if native is None:
            raise IdentityUnavailable('mapped native Group missing')
        if native.group_name != item['name']:
            rename(group, item['name'])
            refreshed = native_lookup(group)
            if refreshed is None or refreshed.group_name != item['name']:
                raise IdentityUnavailable('native Group rename not confirmed')
            renamed += 1
        else:
            unchanged += 1
    return dict(status='OK', revision=snapshot['revision'], entities=len(rows),
                renamed=renamed, unchanged=unchanged, membership_writes=0)


def run(*, settings, actor):
    """Authenticated native CE system-admin entry; obtain only trusted facts."""
    from django.db import connection
    from seaserv import ccnet_api
    from seahub.base.accounts import User
    from seahub.utils.db_api import SeafileDB
    from seahub.utils.ccnet_db import get_ccnet_db_name
    import os
    import pymysql

    config = configuration(settings)
    owner = User.objects.get(email=actor)
    if not owner.is_active or not owner.is_staff:
        raise PermissionError('native service group owner unavailable')
    snapshot = DirectoryClient(config).entities()
    validate_entities(snapshot)  # Reject damaged/partial sources before connecting to native writes.
    default = settings.DATABASES.get('default', {})
    database = SeafileDB().db_name
    if not database:
        raise IdentityUnavailable('native Seafile schema missing')
    with pymysql.connect(
        host=os.environ.get('SEAFILE_MYSQL_DB_HOST') or default.get('HOST') or '127.0.0.1',
        port=int(os.environ.get('SEAFILE_MYSQL_DB_PORT') or default.get('PORT') or 3306),
        user=os.environ.get('SEAFILE_MYSQL_DB_USER') or default.get('USER') or '',
        password=os.environ.get('SEAFILE_MYSQL_DB_PASSWORD') or default.get('PASSWORD') or '',
        database=database, charset='utf8mb4', autocommit=True, connect_timeout=5,
    ) as conn:
        catalog = GroupCatalog(conn, account_schema=get_ccnet_db_name(),
                               provider=config['provider'],
                               create_group=lambda name: ccnet_api.create_group(name, actor))
        return reconcile(snapshot, catalog=catalog,
                         native_lookup=ccnet_api.get_group, rename=ccnet_api.set_group_name)
