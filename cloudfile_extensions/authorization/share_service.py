"""Transactional administrator share commands; no HTTP route or byte grant."""
from datetime import datetime, timezone
from uuid import uuid4

from ..common.errors import ContractError, invalid
from ..common.validation import object_fields
from ..events.outbox import EventWriter
from ..jobs.authority import scope_locks
from ..resources.paths import resource_ref
from .management import DirectoryManagement
from .shares import DirectoryShares, share_value


class DirectoryShareService:
    def __init__(self, management, *, lifecycle_reader):
        if not isinstance(management, DirectoryManagement):
            raise ValueError('transactional directory management authority required')
        self.management = management
        self.store = DirectoryShares(lifecycle_reader=lifecycle_reader)

    def create(self, request):
        object_fields(request, ('reference', 'value'))
        ref, value = resource_ref(request['reference']), share_value(request['value'])
        if ref['kind'] != 'dir' or ref['path'] != value['path']:
            raise invalid('Directory share target mismatch')
        def change(cursor):
            item, created = self.store.create(cursor, ref, value, actor=self.management.actor)
            return item, 'created' if created else None
        return self._change(ref, change)

    def delete(self, share_id, request, *, if_match):
        object_fields(request, ('reference',))
        ref = resource_ref(request['reference'])
        if ref['kind'] != 'dir' or ref['path'] == '/':
            raise invalid('Non-root directory required')
        def change(cursor):
            item = self.store.delete(cursor, ref, share_id, if_match=if_match)
            return dict(id=item['id'], revision=item['revision'], deleted=True), 'deleted'
        return self._change(ref, change)

    def _change(self, ref, change):
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
                        if authority.authorize(cursor, authority.actor, ref) is not True:
                            raise ContractError('ACCESS_DENIED', 'Directory sharing management is not allowed', 403)
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
