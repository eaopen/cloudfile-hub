"""Transaction-owned resource guards and commit intents.

Every caller must hold current resource authorization/lifecycle scopes. This is
persistence, not an authentication API. Native publication is deliberately a
separate, unavailable-by-default adapter; staging content never publishes it.
"""
import hashlib
import hmac
import json
import re
from uuid import UUID, uuid4

from ..common.errors import ContractError
from ..common.validation import identifier
from .storage import require_storage


LIMIT = 2 ** 64 - 1
MODES = {'file-lock', 'checkout'}


def reject(message, code='EDIT_CONFLICT', status=409):
    raise ContractError(code, message, status)


def uuid(value):
    if not isinstance(value, str) or str(UUID(value)) != value:
        raise ValueError('canonical UUID required')
    return value


def hex_value(value, length):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{%d}' % length, value):
        raise ValueError('bounded content identity required')
    return value


def digest(token):
    return hashlib.sha256(hex_value(token, 64).encode()).hexdigest()


def sequence(value):
    if type(value) is not int or not 1 <= value <= LIMIT:
        raise ValueError('positive uint64 required')
    return value


class EditingStore:
    columns = ('repo_id', 'lifecycle_ref', 'guard_id', 'generation', 'mode', 'owner', 'owner_native_user',
               'source', 'holder', 'credential_epoch', 'proof_digest', 'base_file_id',
               'pending_intent', 'lease_until', 'hard_expire_at', 'credential_active', 'recoverable')

    def load(self, sql, uid, repo, lifecycle):
        uuid(uid)
        uuid(repo)
        require_storage(sql)
        identifier(lifecycle, maximum=512)
        # One permanent row serializes every mode and preserves generation.
        sql.execute('INSERT INTO cf_edit_guard(resource_uid,repo_id,lifecycle_ref,generation,credential_epoch) VALUES(%s,%s,%s,0,0) ON DUPLICATE KEY UPDATE resource_uid=resource_uid', (uid, repo, lifecycle))
        sql.execute('SELECT repo_id,lifecycle_ref,guard_id,generation,mode,owner,owner_native_user,source,holder,credential_epoch,proof_digest,base_file_id,pending_intent,lease_until,hard_expire_at,IF(lease_until>UTC_TIMESTAMP(6) AND hard_expire_at>UTC_TIMESTAMP(6),1,0),IF(hard_expire_at>UTC_TIMESTAMP(6),1,0) FROM cf_edit_guard WHERE resource_uid=%s FOR UPDATE', (uid,))
        row = sql.fetchone()
        if row is None:
            return None
        state = dict(zip(self.columns, row))
        if state['repo_id'] != repo or state['lifecycle_ref'] != lifecycle:
            reject('Resource lifecycle changed')
        if type(state['generation']) is not int or not 0 <= state['generation'] <= LIMIT:
            reject('Invalid guard generation', 'EDIT_UNAVAILABLE', 503)
        if state['guard_id'] is None:
            if any(state[key] is not None for key in ('mode', 'owner', 'owner_native_user', 'source', 'holder', 'proof_digest', 'base_file_id', 'pending_intent', 'lease_until', 'hard_expire_at')):
                reject('Inconsistent released guard', 'EDIT_UNAVAILABLE', 503)
        else:
            sequence(state['generation'])
            uuid(state['guard_id'])
            sequence(state['credential_epoch'])
            if state['mode'] not in MODES:
                reject('Unsupported persisted edit mode', 'EDIT_UNAVAILABLE', 503)
            for key, maximum in (('owner', 225), ('source', 32), ('holder', 128)):
                identifier(state[key], maximum=maximum)
            identifier(state['owner_native_user'], maximum=255)
            hex_value(state['proof_digest'], 64)
            if state['mode'] == 'checkout':
                hex_value(state['base_file_id'], 40)
            elif state['base_file_id'] is not None:
                reject('Manual lock cannot carry a checkout baseline', 'EDIT_UNAVAILABLE', 503)
            if state['pending_intent']:
                uuid(state['pending_intent'])
            deadlines = (state['lease_until'], state['hard_expire_at'])
            if (state['mode'] == 'file-lock' and any(deadlines)) or (state['mode'] != 'file-lock' and not all(deadlines)):
                reject('Inconsistent credential deadlines', 'EDIT_UNAVAILABLE', 503)
        return state

    @staticmethod
    def public(row):
        if row is None:
            return dict(active=False, state='released', generation='0')
        result = {key: value for key, value in row.items() if key not in ('proof_digest', 'recoverable', 'owner_native_user')}
        for key in ('generation', 'credential_epoch'):
            result[key] = str(result[key])
        for key in ('lease_until', 'hard_expire_at'):
            result[key] = result[key].isoformat(timespec='microseconds') + 'Z' if result[key] else None
        active = row['guard_id'] is not None
        result.update(active=active, credential_active=bool(row['credential_active']),
                      state='released' if not active else ('active' if row['mode'] == 'file-lock' or row['credential_active'] else 'suspended'))
        return result

    @staticmethod
    def no_pending(row):
        if row['pending_intent']:
            reject('Resolve pending publication before changing ownership', 'EDIT_PENDING')

    @staticmethod
    def native_owner(row, native_user):
        """The authenticated host resolves this from the locked current mapping."""
        identifier(native_user, maximum=255)
        if row and row['guard_id'] and row['owner_native_user'] != native_user:
            reject('Native owner binding changed', 'ACCESS_DENIED', 403)

    @staticmethod
    def proof(row, *, actor, holder, token, guard_id, generation, credential_epoch, live=True):
        expected = digest(token)
        sequence(generation)
        sequence(credential_epoch)
        if (not row or row['guard_id'] != uuid(guard_id) or row['generation'] != generation
                or row['credential_epoch'] != credential_epoch or row['owner'] != actor
                or row['holder'] != holder or not row['proof_digest']
                or not hmac.compare_digest(row['proof_digest'], expected)
                or (live and not row['credential_active'])):
            reject('Editing credential is no longer current')

    def acquire(self, sql, *, uid, repo, lifecycle, actor, holder, token, mode,
                source, base_file_id, native_user=None, seconds=600, hard_seconds=604800,
                replace_generation=None):
        identifier(actor, maximum=225)
        identifier(holder, maximum=128)
        identifier(source, maximum=32)
        identifier(native_user, maximum=255)
        hex_value(base_file_id, 40)
        proof_digest = digest(token)
        if mode not in MODES or type(seconds) is not int or not 60 <= seconds <= 1800:
            raise ValueError('valid editing mode and lease required')
        if type(hard_seconds) is not int or not 1800 <= hard_seconds <= 2592000:
            raise ValueError('bounded server policy required')
        if replace_generation is not None:
            sequence(replace_generation)
        row = self.load(sql, uid, repo, lifecycle)
        if row and row['guard_id']:
            self.native_owner(row, native_user)
            # Only an owner manual lock can explicitly become an edit session.
            if (replace_generation != row['generation'] or row['mode'] != 'file-lock'
                    or row['owner'] != actor):
                reject('Resource is reserved', 'RESOURCE_LOCKED', 423)
            self.no_pending(row)
        elif replace_generation is not None:
            reject('Conversion target no longer exists')
        generation = row['generation'] + 1
        if generation > LIMIT:
            reject('Guard generation exhausted', 'EDIT_UNAVAILABLE', 503)
        guard_id = str(uuid4())
        sql.execute('UPDATE cf_edit_guard SET guard_id=%s,generation=%s,mode=%s,owner=%s,owner_native_user=%s,source=%s,holder=%s,credential_epoch=1,proof_digest=%s,base_file_id=%s,pending_intent=NULL,lease_until=IF(%s, NULL,TIMESTAMPADD(SECOND,%s,UTC_TIMESTAMP(6))),hard_expire_at=IF(%s,NULL,TIMESTAMPADD(SECOND,%s,UTC_TIMESTAMP(6))) WHERE resource_uid=%s',
                    (guard_id, generation, mode, actor, native_user, source, holder, proof_digest, base_file_id if mode == 'checkout' else None,
                     mode == 'file-lock', seconds, mode == 'file-lock', hard_seconds, uid))
        return self.public(self.load(sql, uid, repo, lifecycle))

    def renew(self, sql, *, uid, repo, lifecycle, seconds=600, **proof):
        if type(seconds) is not int or not 60 <= seconds <= 1800:
            raise ValueError('bounded lease required')
        row = self.load(sql, uid, repo, lifecycle)
        self.proof(row, **proof)
        sql.execute('UPDATE cf_edit_guard SET lease_until=LEAST(hard_expire_at,TIMESTAMPADD(SECOND,%s,UTC_TIMESTAMP(6))) WHERE resource_uid=%s', (seconds, uid))
        return self.public(self.load(sql, uid, repo, lifecycle))

    def resume(self, sql, *, uid, repo, lifecycle, actor, guard_id, generation,
               credential_epoch, holder, token, expected_file_id):
        # Caller reauthenticates and reads the real native version under authority.
        row = self.load(sql, uid, repo, lifecycle)
        if (not row or row['guard_id'] != uuid(guard_id) or row['generation'] != sequence(generation)
                or row['credential_epoch'] != sequence(credential_epoch) or row['owner'] != actor
                or row['mode'] == 'file-lock' or not row['recoverable']
                or row['base_file_id'] != hex_value(expected_file_id, 40)):
            reject('Reservation cannot be resumed')
        self.no_pending(row)
        identifier(holder, maximum=128)
        new_digest = digest(token)
        if row['credential_epoch'] == LIMIT or hmac.compare_digest(row['proof_digest'], new_digest):
            reject('Fresh credential required')
        sql.execute('UPDATE cf_edit_guard SET holder=%s,proof_digest=%s,credential_epoch=credential_epoch+1,lease_until=LEAST(hard_expire_at,TIMESTAMPADD(SECOND,600,UTC_TIMESTAMP(6))) WHERE resource_uid=%s', (holder, new_digest, uid))
        return self.public(self.load(sql, uid, repo, lifecycle))

    def release(self, sql, *, uid, repo, lifecycle, actor, guard_id, generation,
                management=False, reason=None, proof=None):
        row = self.load(sql, uid, repo, lifecycle)
        if not row or row['guard_id'] != uuid(guard_id) or row['generation'] != sequence(generation):
            reject('Reservation changed')
        if management:
            # This internal flag is supplied only by a current management authority.
            if not isinstance(reason, str) or not reason.strip() or len(reason) > 512 or any(ord(c) < 32 for c in reason):
                raise ValueError('management recovery reason required')
        elif row['owner'] != actor:
            reject('Reservation belongs to another owner', 'ACCESS_DENIED', 403)
        elif row['mode'] != 'file-lock':
            self.proof(row, actor=actor, guard_id=guard_id, generation=generation, live=False, **(proof or {}))
        self.no_pending(row)
        self._release(sql, uid, repo, row)
        return self.public(self.load(sql, uid, repo, lifecycle))

    @staticmethod
    def _release(sql, uid, repo, row):
        sql.execute('UPDATE cf_edit_guard SET guard_id=NULL,mode=NULL,owner=NULL,owner_native_user=NULL,source=NULL,holder=NULL,credential_epoch=0,proof_digest=NULL,base_file_id=NULL,pending_intent=NULL,lease_until=NULL,hard_expire_at=NULL WHERE resource_uid=%s', (uid,))

    def prepare(self, sql, *, uid, repo, lifecycle, intent_id, expected_file_id,
                staged_file_id, content_digest, action, snapshot=None, **proof):
        uuid(intent_id)
        hex_value(expected_file_id, 40)
        if staged_file_id is not None:
            hex_value(staged_file_id, 40)
        hex_value(content_digest, 64)
        if action not in ('commit', 'checkin', 'checkin-unchanged'):
            raise ValueError('publication action required')
        if snapshot is not None:
            from ..common.validation import object_fields
            object_fields(snapshot, ('id', 'size', 'source'))
            uuid(snapshot['id'])
            if type(snapshot['size']) is not int or not 0 <= snapshot['size'] <= 128 * 1024 * 1024:
                raise ValueError('bounded immutable snapshot required')
            identifier(snapshot['source'], maximum=512)
        row = self.load(sql, uid, repo, lifecycle)
        self.proof(row, **proof)
        request = dict(uid=uid, guard_id=row['guard_id'], generation=row['generation'],
                       credential_epoch=row['credential_epoch'], expected_file_id=expected_file_id,
                       staged_file_id=staged_file_id, content_digest=content_digest, action=action, snapshot=snapshot)
        request_digest = hashlib.sha256(json.dumps(request, sort_keys=True).encode()).hexdigest()
        sql.execute('SELECT request_digest FROM cf_commit_intent WHERE intent_id=%s FOR UPDATE', (intent_id,))
        prior = sql.fetchone()
        if prior:
            if prior[0] != request_digest:
                reject('Intent identity reused for another request', 'IDEMPOTENCY_CONFLICT')
            return self.intent(sql, uid=uid, intent_id=intent_id)
        self.no_pending(row)
        if row['base_file_id'] != expected_file_id:
            reject('Content baseline changed', 'RESOURCE_VERSION_CONFLICT')
        sql.execute("INSERT INTO cf_commit_intent(intent_id,resource_uid,guard_id,generation,credential_epoch,request_digest,expected_file_id,staged_file_id,content_digest,action,snapshot,state,created_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'prepared',UTC_TIMESTAMP(6))",
                    (intent_id, uid, row['guard_id'], row['generation'], row['credential_epoch'], request_digest,
                     expected_file_id, staged_file_id, content_digest, action, json.dumps(snapshot) if snapshot is not None else None))
        sql.execute('UPDATE cf_edit_guard SET pending_intent=%s WHERE resource_uid=%s', (intent_id, uid))
        return self.intent(sql, uid=uid, intent_id=intent_id)

    @staticmethod
    def intent(sql, *, uid, intent_id):
        uuid(uid)
        uuid(intent_id)
        sql.execute('SELECT resource_uid,guard_id,generation,credential_epoch,expected_file_id,staged_file_id,content_digest,action,state,result_file_id,result_commit_id,snapshot,created_at FROM cf_commit_intent WHERE intent_id=%s FOR UPDATE', (intent_id,))
        row = sql.fetchone()
        if not row or row[0] != uid:
            reject('Intent not found', 'NOT_FOUND', 404)
        keys = ('resource_uid','guard_id','generation','credential_epoch','expected_file_id','staged_file_id','content_digest','action','state','result_file_id','result_commit_id')
        metadata = json.loads(row[11]) if row[11] is not None else None
        if metadata is not None:
            metadata.update(sha256=row[6], created_at=row[12].isoformat(timespec='microseconds') + 'Z')
        return dict(zip(keys, row[:11]), intent_id=intent_id, snapshot=metadata,
                    checked_in=row[8] == 'published' and row[7] in ('checkin', 'checkin-unchanged'))

    def cancel_prepared(self, sql, *, uid, repo, lifecycle, intent_id, **proof):
        row = self.load(sql, uid, repo, lifecycle)
        self.proof(row, live=False, **proof)
        intent = self.intent(sql, uid=uid, intent_id=intent_id)
        if intent['state'] != 'prepared' or row['pending_intent'] != intent_id:
            reject('Only an unpublished prepared intent can be cancelled')
        sql.execute("UPDATE cf_commit_intent SET state='cancelled' WHERE intent_id=%s", (intent_id,))
        sql.execute('UPDATE cf_edit_guard SET pending_intent=NULL WHERE resource_uid=%s', (uid,))
        return self.intent(sql, uid=uid, intent_id=intent_id)
