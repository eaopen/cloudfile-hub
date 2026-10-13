"""Explicit, revision-checked subtree revocation; never implicit cascade."""
from datetime import datetime, timezone
from uuid import uuid4

from ..common.conditions import compare_if_match
from ..common.errors import ContractError, invalid
from ..common.validation import object_fields
from ..events.outbox import EventWriter
from ..resources.paths import resource_ref, is_descendant_or_equal
from .directory_management import DirectoryAdminRules
from .service import DirectoryPolicyService
from .share_service import DirectoryShareService


class DirectoryScopeService(DirectoryShareService):
    operation_namespace = 'directory_scope'

    def store_for(self, domain):
        if domain == 'shares':
            return 'cf_dir_share', self.store
        if domain == 'acl':
            return 'cf_dir_acl', self.management.rules
        if domain == 'admins':
            return 'cf_dir_admin', DirectoryAdminRules(self.management.state.connection,
                provider=self.management.state.provider, actor=self.management.actor,
                request_id=self.management.rules.request_id, authorize=lambda *args: False)
        raise invalid('Invalid directory policy domain')

    def list_scope(self, request, *, limit=50, after=None):
        object_fields(request, ('reference', 'domain'))
        ref = resource_ref(request['reference'])
        if ref['kind'] != 'dir' or type(limit) is not int or not 1 <= limit <= 100:
            raise invalid('Directory and bounded page required')
        if after is not None:
            DirectoryPolicyService._id(after)
        table, store = self.store_for(request['domain'])
        prefix = ref['path'].rstrip('/') + '/'
        def read(cursor):
            sql = ('SELECT ' + store.FIELDS + ' FROM ' + table + ' WHERE repo_id=%s '
                'AND (path=%s OR LEFT(path,CHAR_LENGTH(%s))=%s)')
            values = [ref['repo_id'], ref['path'], prefix, prefix]
            if after:
                sql += ' AND id>%s'
                values.append(after)
            cursor.execute(sql + ' ORDER BY id LIMIT %s FOR UPDATE', (*values, limit + 1))
            rows = [store._decode(row) for row in cursor.fetchall()]
            return dict(items=rows[:limit], next_after=rows[limit - 1]['id'] if len(rows) > limit else None), None
        return self._change(ref, read)

    def revoke(self, request, *, idempotency_key):
        object_fields(request, ('reference', 'domain', 'items'))
        ref = resource_ref(request['reference'])
        items = request['items']
        if ref['kind'] != 'dir' or not isinstance(items, list) or not 1 <= len(items) <= 100:
            raise invalid('Explicit bounded revocation required')
        domain = request['domain']
        table, store = self.store_for(domain)
        ids = set()
        for item in items:
            object_fields(item, ('id', 'etag'))
            id_ = DirectoryPolicyService._id(item['id'])
            DirectoryPolicyService._condition(item['etag'])
            if id_ in ids:
                raise invalid('Duplicate revocation target')
            ids.add(id_)
        def change(cursor):
            removed = []
            for item in sorted(items, key=lambda value: value['id']):
                cursor.execute('SELECT ' + store.FIELDS + ' FROM ' + table +
                    ' WHERE repo_id=%s AND id=%s FOR UPDATE', (ref['repo_id'], item['id']))
                rows = cursor.fetchall()
                if len(rows) != 1:
                    raise ContractError('PRECONDITION_FAILED', 'Revocation target changed', 412)
                value = store._decode(rows[0])
                if not is_descendant_or_equal(value['path'], ref['path']):
                    raise ContractError('ACCESS_DENIED', 'Revocation target is outside directory', 403)
                if not self.management.covers(value['path'], descendants=bool(value.get('inherit', True)),
                        strictly_below=domain == 'admins'):
                    raise ContractError('ACCESS_DENIED', 'Revocation exceeds management scope', 403)
                compare_if_match(item['etag'], value['etag'])
                cursor.execute('DELETE FROM ' + table + ' WHERE repo_id=%s AND id=%s AND revision=%s',
                    (ref['repo_id'], value['id'], value['revision']))
                if cursor.rowcount != 1:
                    raise ContractError('PRECONDITION_FAILED', 'Revocation target changed', 412)
                EventWriter().append(cursor, dict(event_id=str(uuid4()),
                    occurred_at=datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                    request_id=self.management.rules.request_id, actor_user_id=self.management.actor,
                    actor_kind='user', source='hub', action={'acl': 'acl.deleted', 'admins': 'directory_admin.deleted',
                        'shares': 'directory_share.deleted'}[domain], result='succeeded', repo_id=ref['repo_id'],
                    path=value['path'], resource_kind=value.get('kind', 'dir'), policy_revision=value['revision']))
                removed.append(dict(id=value['id'], path=value['path'], deleted=True))
            # One domain per request: shared READ never mutates ACL records.
            return dict(domain=domain, reference=ref, items=removed), None
        return self._change(ref, change, idempotency_key=DirectoryPolicyService._key(idempotency_key),
            payload=dict(action='revoke', **request))
