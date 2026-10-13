"""Transactional administrator share commands; never issue byte grants."""
from datetime import datetime, timezone
import json
from uuid import uuid4

from ..common.errors import ContractError, invalid
from ..common.validation import object_fields
from ..events.outbox import EventWriter
from ..jobs.authority import scope_locks
from ..resources.paths import resource_ref
from .management import DirectoryManagement
from .shares import DirectoryShares, share_value


class DirectoryShareService:
    operation_namespace = 'directory_share'
    def __init__(self, management, *, lifecycle_reader):
        if not isinstance(management, DirectoryManagement):
            raise ValueError('transactional directory management authority required')
        self.management = management
        self.store = DirectoryShares(lifecycle_reader=lifecycle_reader)

    def create(self, request, *, idempotency_key=None):
        object_fields(request, ('reference', 'value'))
        ref, value = resource_ref(request['reference']), share_value(request['value'])
        if ref['kind'] != 'dir' or ref['path'] != value['path']:
            raise invalid('Directory share target mismatch')
        def change(cursor):
            item, created = self.store.create(cursor, ref, value, actor=self.management.actor)
            return item, 'created' if created else None
        return self._change(ref, change, idempotency_key=idempotency_key, payload=dict(action='create', value=value))

    def delete(self, share_id, request, *, if_match, idempotency_key=None):
        object_fields(request, ('reference',))
        ref = resource_ref(request['reference'])
        if ref['kind'] != 'dir' or ref['path'] == '/':
            raise invalid('Non-root directory required')
        def change(cursor):
            item = self.store.delete(cursor, ref, share_id, if_match=if_match)
            return dict(id=item['id'], revision=item['revision'], deleted=True), 'deleted'
        return self._change(ref, change, idempotency_key=idempotency_key,
            payload=dict(action='delete', id=share_id, if_match=if_match))

    def list(self, request, *, limit=50, after=None):
        from .service import DirectoryPolicyService
        from .rules import digest
        object_fields(request, ('reference',))
        ref = resource_ref(request['reference'])
        if ref['kind'] != 'dir' or type(limit) is not int or not 1 <= limit <= 100:
            raise invalid('Directory and bounded page required')
        if after is not None:
            DirectoryPolicyService._id(after)
        def read(cursor):
            sql = 'SELECT ' + self.store.FIELDS + ' FROM cf_dir_share WHERE repo_id=%s AND path_hash=%s'
            params = [ref['repo_id'], digest(ref['path'])]
            if after is not None:
                sql += ' AND id>%s'
                params.append(after)
            sql += ' ORDER BY id LIMIT %s FOR UPDATE'
            params.append(limit + 1)
            cursor.execute(sql, tuple(params))
            rows = [self.store._decode(row) for row in cursor.fetchall()]
            if any(row['path'] != ref['path'] for row in rows):
                raise ContractError('POLICY_UNAVAILABLE', 'Invalid share location', 503)
            return dict(items=rows[:limit], next_after=rows[limit - 1]['id'] if len(rows) > limit else None), None
        return self._change(ref, read)

    def _change(self, ref, change, *, idempotency_key=None, payload=None):
        authority = self.management
        authority.preparation.prepare(authority.actor)
        connection = authority.state.connection
        scopes = [dict(type='provider', provider=authority.state.provider, external_id=authority.state.provider),
            dict(type='user', provider=authority.state.provider, external_id=authority.actor),
            dict(type='repo', provider='cloudfile', external_id=ref['repo_id'])]
        try:
            with scope_locks(connection, scopes):
                connection.begin()
                try:
                    with connection.cursor() as cursor:
                        authorize = getattr(authority, 'authorize_share', authority.authorize)
                        if authorize(cursor, authority.actor, ref) is not True:
                            raise ContractError('ACCESS_DENIED', 'Directory sharing management is not allowed', 403)
                        key = None
                        if idempotency_key is not None:
                            from .service import DirectoryPolicyService
                            from .requests import require_storage
                            from .rules import digest
                            DirectoryPolicyService._key(idempotency_key)
                            key = digest(json.dumps([self.operation_namespace, authority.state.provider,
                                authority.actor, ref, idempotency_key], sort_keys=True))
                            fingerprint = digest(json.dumps(payload, sort_keys=True))
                            require_storage(cursor)
                            cursor.execute('SELECT request_digest,result_json FROM cf_policy_request WHERE request_key=%s FOR UPDATE', (key,))
                            saved = cursor.fetchall()
                            if saved:
                                if len(saved) != 1 or saved[0][0] != fingerprint:
                                    raise ContractError('IDEMPOTENCY_CONFLICT', 'Key was used for another share request', 409)
                                result = json.loads(saved[0][1])
                                if not isinstance(result, dict):
                                    raise ValueError('invalid saved share result')
                                authority._barriers(ref['repo_id'])
                                authority.finalize(cursor)
                                connection.commit()
                                return result
                        result, action = change(cursor)
                        if action is not None:
                            # Enrollment closes legacy unguarded publication.
                            cursor.execute('INSERT INTO cf_managed_library(repo_id,created_at) VALUES(%s,UTC_TIMESTAMP(6)) '
                                'ON DUPLICATE KEY UPDATE repo_id=VALUES(repo_id)', (ref['repo_id'],))
                            EventWriter().append(cursor, dict(event_id=str(uuid4()),
                                occurred_at=datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                                request_id=authority.rules.request_id, actor_user_id=authority.actor,
                                actor_kind='user', source='hub', action='directory_share.' + action,
                                result='succeeded', repo_id=ref['repo_id'], path=ref['path'],
                                resource_kind='dir', policy_revision=result['revision']))
                        if key is not None:
                            cursor.execute('INSERT INTO cf_policy_request(request_key,request_digest,result_json,inherited_effect,created_at) '
                                'VALUES(%s,%s,%s,1,UTC_TIMESTAMP(6))', (key, fingerprint,
                                json.dumps(result, ensure_ascii=False, sort_keys=True)))
                        authority._barriers(ref['repo_id'])
                        authority.finalize(cursor)
                    connection.commit()
                    return result
                finally:
                    connection.rollback()
        except ContractError:
            raise
        except Exception:
            raise ContractError('POLICY_UNAVAILABLE', 'Directory share mutation is unavailable', 503) from None
        finally:
            authority.epoch = None
            authority.current_subject = None
            authority.is_owner = False
            authority.is_library_admin = False
            authority.is_global_library_admin = False
