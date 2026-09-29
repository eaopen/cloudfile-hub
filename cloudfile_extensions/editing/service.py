"""Single-file manual workflow behind current CloudFile resource authorities.

No HTTP registration. Device/third-party transports must resolve authenticated
identity before constructing this service, never forward actor from a body.
"""
import hashlib
from uuid import uuid4

from ..common.errors import ContractError
from ..common.validation import object_fields, sequence
from ..resources.requests import execute
from datetime import datetime, timezone
from ..events.outbox import EventWriter
from ..resources.service import ResourceService
from ..resources.paths import resource_ref
from .store import EditingStore
from .authority import LockManagementAuthority


class EditingService:
    fields = {
        'checkout': (('reference', 'base_file_id', 'token'), ()),
        'file-lock': (('reference', 'base_file_id', 'token'), ()),
        'heartbeat': (('reference', 'guard_id', 'generation', 'credential_epoch', 'token'), ()),
        'resume': (('reference', 'guard_id', 'generation', 'credential_epoch', 'token', 'base_file_id'), ()),
        'prepare': (('reference', 'guard_id', 'generation', 'credential_epoch', 'token', 'intent_id', 'base_file_id', 'content_digest', 'action'), ('staged_file_id', 'snapshot')),
        'cancel': (('reference', 'guard_id', 'generation', 'credential_epoch', 'token', 'intent_id'), ()),
        'abandon': (('reference', 'guard_id', 'generation', 'credential_epoch', 'token'), ()),
        'force-release': (('reference', 'guard_id', 'generation', 'reason'), ()),
        'unlock': (('reference', 'guard_id', 'generation'), ()),
    }

    def __init__(self, resources, *, holder, version_reader, source, management=None):
        if not isinstance(resources, ResourceService) or not callable(version_reader):
            raise ValueError('actual resource service and native version reader required')
        self.resources, self.holder, self.version_reader = resources, holder, version_reader
        self.events = EventWriter()
        from ..common.validation import identifier
        identifier(source, maximum=32)
        identifier(holder, maximum=128)
        if management is not None and (not isinstance(management, LockManagementAuthority)
                or management.state.connection is not resources.store.connection
                or management.actor != resources.write_authority.actor):
            raise ValueError('same-connection current management authority required')
        self.management = management
        self.source = source
        self.edits = EditingStore()

    @staticmethod
    def _reference(value):
        ref = resource_ref(value)
        if ref['kind'] != 'file' or len(ref['path'].encode()) > 4096:
            raise ValueError('bounded single file required')
        return ref

    def _resource(self, sql, ref):
        store = self.resources.store
        evidence = store._validate_evidence(self.resources.reader(sql, ref))
        return evidence, store._row(ref, evidence, locking=True)

    def _audit(self, sql, ref, uid, action, guard, reason=None):
        self.events.append(sql, dict(event_id=str(uuid4()), request_id=self.resources.request_id,
            occurred_at=datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            actor_user_id=self.resources.write_authority.actor, actor_kind='user', source='hub',
            action=action, result='succeeded', repo_id=ref['repo_id'], path=ref['path'],
            resource_uid=uid, resource_kind='file', revision=guard['fencing'],
            **({'reason': reason} if reason is not None else {})))

    def query(self, request):
        object_fields(request, ('reference',), ('intent_id',))
        ref = self._reference(request['reference'])
        def read(sql, reference):
            evidence, row = self._resource(sql, reference)
            if not row:
                if 'intent_id' in request:
                    raise ContractError('NOT_FOUND', 'Intent not found', 404)
                return self.edits.public(None)
            # A current read authority is still required for historical receipts.
            if 'intent_id' in request:
                result = self.edits.intent(sql, uid=row['uid'], intent_id=request['intent_id'])
                for key in ('generation', 'credential_epoch'):
                    result[key] = str(result[key])
                return result
            return self.edits.public(self.edits.load(sql, row['uid'], ref['repo_id'], evidence.lifecycle_ref))
        return self.resources.read_authority.consume(ref, read)

    def command(self, operation, request, *, idempotency_key):
        if operation not in self.fields:
            raise ContractError('EDIT_UNAVAILABLE', 'Editing operation is not supported', 503)
        object_fields(request, *self.fields[operation])
        ref = self._reference(request['reference'])
        authority = self.resources.write_authority
        if operation == 'force-release':
            reason = request['reason']
            if not isinstance(reason, str) or not reason.strip() or len(reason) > 512 or any(ord(c) < 32 for c in reason):
                raise ValueError('bounded management reason required')
            if self.management is None:
                raise ContractError('EDIT_UNAVAILABLE', 'Management authority unavailable', 503)
            authority = self.management
        actor = authority.actor
        if 'token' in request:
            from .store import digest
            digest(request['token'])
        protected = {key: value for key, value in request.items() if key != 'token'}
        protected.update(holder=self.holder, source=self.source)
        if 'token' in request:
            protected['proof_digest'] = hashlib.sha256(request['token'].encode()).hexdigest()

        def apply(sql, reference):
            if operation == 'checkout':
                # Enroll before the lifecycle reader pins Branch. Legacy final
                # publications also lock this marker before Branch, so a write
                # that passed an earlier lock preflight cannot bypass Checkout.
                # Enrollment uses the existing policy gate and is monotonic.
                sql.execute("INSERT INTO cf_managed_library(repo_id,created_at) VALUES(%s,UTC_TIMESTAMP(6)) "
                    "ON DUPLICATE KEY UPDATE repo_id=VALUES(repo_id)", (ref['repo_id'],))
            evidence, row = self._resource(sql, reference)
            if row is None:
                # Bind sparse resource identity under current native authority.
                if operation not in ('checkout', 'file-lock'):
                    raise ContractError('NOT_FOUND', 'Editing reservation not found', 404)
                uid = str(uuid4())
                sql.execute("INSERT INTO cf_resource(uid,repo_id,kind,path,path_hash,lifecycle_ref,revision,state,updated_at) VALUES(%s,%s,'file',%s,%s,%s,1,'active',UTC_TIMESTAMP(6))", (uid, ref['repo_id'], ref['path'], self.resources.store._hash(ref['path']), evidence.lifecycle_ref))
                self.resources.store.mutation_hook(sql, dict(action='resource.attributes.updated', actor_user_id=actor,
                    resource_uid=uid, repo_id=ref['repo_id'], path=ref['path'], revision='1'))
                row = self.resources.store._row(reference, evidence, locking=True)
            target = dict(uid=row['uid'], repo=ref['repo_id'], lifecycle=evidence.lifecycle_ref)
            def mutate():
                # authorize() has locked the current two-axis identity mapping.
                # A request username is never accepted, and a changed binding
                # cannot reuse an existing guard or mint replacement credentials.
                native_user = authority.state.username(actor)
                if operation != 'force-release':
                    self.edits.native_owner(self.edits.load(sql, **target), native_user)
                if operation in ('checkout', 'file-lock', 'resume'):
                    if self.version_reader(sql, ref, evidence) != request['base_file_id']:
                        raise ContractError('RESOURCE_VERSION_CONFLICT', 'Native content changed', 409)
                if operation in ('checkout', 'file-lock'):
                    result = self.edits.acquire(sql, **target, actor=actor, holder=self.holder,
                        token=request['token'], source=self.source, mode=operation, base_file_id=request['base_file_id'],
                        native_user=native_user)
                elif operation == 'resume':
                    result = self.edits.resume(sql, **target, actor=actor, holder=self.holder,
                        token=request['token'], guard_id=request['guard_id'], generation=sequence(request['generation']),
                        credential_epoch=sequence(request['credential_epoch']), expected_file_id=request['base_file_id'])
                elif operation == 'force-release':
                    result = self.edits.release(sql, **target, actor=actor, guard_id=request['guard_id'],
                        generation=sequence(request['generation']), management=True, reason=request['reason'])
                elif operation == 'unlock':
                    current = self.edits.load(sql, **dict(uid=target['uid'], repo=target['repo'], lifecycle=target['lifecycle']))
                    if not current or current['mode'] != 'file-lock':
                        raise ContractError('EDIT_CONFLICT', 'Manual lock required', 409)
                    result = self.edits.release(sql, **target, actor=actor, guard_id=request['guard_id'], generation=sequence(request['generation']))
                else:
                    proof = dict(actor=actor, holder=self.holder, token=request['token'], guard_id=request['guard_id'],
                                 generation=sequence(request['generation']), credential_epoch=sequence(request['credential_epoch']))
                    if operation == 'heartbeat':
                        result = self.edits.renew(sql, **target, **proof)
                    elif operation == 'prepare':
                        result = self.edits.prepare(sql, **target, **proof, intent_id=request['intent_id'],
                            expected_file_id=request['base_file_id'], staged_file_id=request.get('staged_file_id'),
                            content_digest=request['content_digest'], action=request['action'], snapshot=request.get('snapshot'))
                    elif operation == 'cancel':
                        result = self.edits.cancel_prepared(sql, **target, **proof, intent_id=request['intent_id'])
                    else:
                        result = self.edits.release(sql, **target, actor=actor, guard_id=proof['guard_id'], generation=proof['generation'],
                            proof={key: proof[key] for key in ('holder', 'token', 'credential_epoch')})
                for key in ('generation', 'credential_epoch'):
                    if key in result:
                        result[key] = str(result[key])
                self._audit(sql, ref, row['uid'], 'editing.' + operation, {'fencing': str(result['generation'])}, reason=request.get('reason'))
                return result, True
            receipt, _ = execute(sql, provider=self.resources.write_authority.state.provider,
                actor=actor, operation='editing.' + operation, key=idempotency_key, request=protected,
                lifecycle=evidence.lifecycle_ref, secret=self.resources.store.secret, mutate=mutate)
            return dict(receipt=receipt, current_guard=self.edits.public(self.edits.load(sql, **target)))
        return authority.consume(ref, apply)
