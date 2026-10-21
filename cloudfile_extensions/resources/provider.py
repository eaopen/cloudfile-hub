"""eTech provider's bounded namespace replacement in existing user authority."""
from uuid import uuid4

from ..common.conditions import compare_revision
from ..common.errors import ContractError, invalid
from ..common.validation import identifier, object_fields
from ..identity.service_tokens import ServiceTokenVerifier
from ..tags.bindings import replace_system_tags
from ..tags.definitions import system_definition
from ..tags.read import bound_tags
from ..tags.write import create_system, patch_system
from .paths import resource_ref
from .requests import execute


class SystemTagProvider:
    def __init__(self, verifier, grants):
        if not isinstance(verifier, ServiceTokenVerifier) or not isinstance(grants, dict) or not grants:
            raise ValueError('trusted system-tag verifier and source grants required')
        self.verifier, self.grants = verifier, {}
        for service, value in grants.items():
            identifier(service)
            object_fields(value, ('provider', 'namespaces'))
            identifier(value['provider'], maximum=32)
            namespaces = value['namespaces']
            if not isinstance(namespaces, (list, tuple)) or not namespaces or len(namespaces) > 128:
                raise ValueError('bounded namespace grants required')
            for namespace in namespaces:
                identifier(namespace)
                if namespace.startswith('user:'):
                    raise ValueError('user namespace cannot be maintained by a system provider')
            self.grants[service] = (value['provider'], frozenset(namespaces))

    def replace(self, service, request, *, credential, key):
        principal = self.verifier.verify(credential)
        principal.require('tags.system.write')
        source = self.grants.get(principal.service_id)
        if source is None:
            raise ContractError('ACCESS_DENIED', 'System tag provider is not allowed', 403)
        provider, namespaces = source
        object_fields(request, ('reference', 'revision', 'updates'))
        ref = resource_ref(request['reference'])
        updates = request['updates']
        if not isinstance(updates, list) or not 1 <= len(updates) <= 128:
            raise invalid('Invalid namespace updates')
        normalized, used, count = [], set(), 0
        for update in updates:
            object_fields(update, ('namespace', 'values'))
            namespace, values = update['namespace'], update['values']
            if not isinstance(namespace, str) or namespace not in namespaces:
                raise ContractError('ACCESS_DENIED', 'System tag namespace is not allowed', 403)
            if namespace in used or not isinstance(values, list):
                raise invalid('Duplicate namespace or invalid tag values')
            used.add(namespace)
            candidates = []
            for value in values:
                object_fields(value, ('code',), ('label', 'color', 'enabled'))
                candidate = system_definition(str(uuid4()), provider=provider, namespace=namespace,
                    code=value['code'], value={k: v for k, v in value.items() if k != 'code'})
                candidates.append({k: candidate[k] for k in ('code', 'label', 'color', 'enabled')})
            count += len(candidates)
            if count > 128 or len({item['code'] for item in candidates}) != len(candidates):
                raise invalid('Too many or duplicate system tags')
            normalized.append(dict(namespace=namespace, values=candidates))
        store, authority = service.store, service.write_authority
        def write(cursor, target):
            evidence = store._validate_evidence(service.reader(cursor, target))
            store._row(target, evidence, locking=True)
            def mutate():
                row = store._row(target, evidence, locking=True)
                old = store._snapshot(target, evidence, row)
                compare_revision(request['revision'], old['revision'])
                actor = authority.actor
                def definition_allowed(cursor, who, source_provider, namespace, repo):
                    self.verifier.assert_active(principal)
                    return who == actor and source_provider == provider and namespace in namespaces and repo is None
                def binding_allowed(cursor, who, reference, source_provider, namespace):
                    self.verifier.assert_active(principal)
                    return who == actor and reference == target and source_provider == provider and namespace in namespaces
                if row is None and not count:
                    return {**old, 'tags': []}, False
                if row is None:
                    row = dict(uid=str(uuid4()), path=target['path'], lifecycle_ref=evidence.lifecycle_ref,
                        revision=1, description=None, local_open_type=None)
                    cursor.execute("INSERT INTO cf_resource(uid,repo_id,kind,path,path_hash,lifecycle_ref,revision,state,updated_at) VALUES(%s,%s,%s,%s,%s,%s,1,'active',UTC_TIMESTAMP(6))",
                        (row['uid'], target['repo_id'], target['kind'], target['path'], store._hash(target['path']), evidence.lifecycle_ref))
                revision, changed = row['revision'], False
                for update in normalized:
                    ids = []
                    for value in update['values']:
                        definition, created = create_system(cursor, provider=provider,
                            namespace=update['namespace'], code=value['code'],
                            value={k: v for k, v in value.items() if k != 'code'}, scope_repo_id=None,
                            actor=actor, request_id=service.request_id, authorize_namespace=definition_allowed)
                        if not created:
                            definition, _ = patch_system(cursor, tag_id=definition['tag_id'], provider=provider,
                                namespace=update['namespace'], scope_repo_id=None,
                                changes={k: v for k, v in value.items() if k != 'code'}, if_match=definition['etag'],
                                actor=actor, request_id=service.request_id, authorize_namespace=definition_allowed)
                        ids.append(definition['tag_id'])
                    revision, updated = replace_system_tags(cursor, reference=target, resource_uid=row['uid'],
                        lifecycle_ref=evidence.lifecycle_ref, expected_revision=revision, tag_ids=ids,
                        actor=actor, request_id=service.request_id, provider=provider, namespace=update['namespace'],
                        authorize_namespace=binding_allowed)
                    changed = changed or updated
                self.verifier.assert_active(principal)
                return {**store._snapshot(target, evidence, {**row, 'revision': revision}),
                    'tags': bound_tags(cursor, resource_uid=row['uid'], repo_id=target['repo_id'])}, changed
            return execute(cursor, provider=authority.state.provider, actor=authority.actor,
                operation='tags.system.replace', key=key, request=dict(reference=target,
                    revision=request['revision'], service=principal.service_id, provider=provider, updates=normalized),
                lifecycle=evidence.lifecycle_ref, secret=store.secret, mutate=mutate)
        return authority.consume(ref, write)
