"""Request-scoped attributes/tag domain consumer; no URL registration.

Native lifecycle reader remains a required trusted data-plane adapter, not a
request field. Strong revisions do not themselves prove authorization.
"""
from copy import deepcopy

from ..authorization.read import ContentReadAuthority, ContentMetadataWriteAuthority, LibraryTagManagementAuthority
from ..common.errors import ContractError, invalid
from ..common.validation import object_fields
from .events import ResourceMutationEvents
from .paths import resource_ref
from .store import ResourceStore


class ResourceService:
    def __init__(self, preparation, core, *, cloud_mode, request_id, secret, lifecycle_reader):
        if not callable(lifecycle_reader):
            raise ValueError("authoritative transactional lifecycle reader required")
        self.reader = lifecycle_reader
        self.read_authority = ContentReadAuthority(preparation, core, request_id=request_id, cloud_mode=cloud_mode)
        self.write_authority = ContentMetadataWriteAuthority(preparation, core, request_id=request_id, cloud_mode=cloud_mode)
        self.tag_management = LibraryTagManagementAuthority(preparation, core, request_id=request_id, cloud_mode=cloud_mode)
        self.request_id = request_id
        # The authorized operations never invoke these legacy preflight hooks.
        # Fail closed if a future caller accidentally selects the old pathway.
        def unavailable(*args, **kwargs):
            raise ContractError("PATH_STATE_PENDING", "Legacy resource preflight is unavailable", 503)
        self.store = ResourceStore(preparation.state.connection, inspector=unavailable,
            write_guard=unavailable, secret=secret,
            mutation_hook=ResourceMutationEvents(actor=preparation.actor, request_id=request_id))

    def resolve(self, request):
        object_fields(request, ("reference",))
        return self.store.resolve_authorized(resource_ref(request["reference"]),
            authority=self.read_authority, lifecycle_reader=self.reader, include_tags=True)

    def batch_resolve(self, request):
        """Bounded read-only list enrichment, never allocation or tag scanning."""
        import time
        from contextlib import ExitStack
        from ..jobs.authority import scope_locks
        object_fields(request, ("references",))
        values = request["references"]
        if not isinstance(values, list) or not 1 <= len(values) <= 100:
            raise invalid("Resource batch requires one to one hundred references")
        references = [resource_ref(value) for value in values]
        # The service fixes actor/provider/context for the entire request. Only
        # repositories split groups; normalized duplicates share one decision
        # and snapshot, then expand back to the caller's original slot order.
        def key(ref):
            return (ref["repo_id"], ref["kind"], ref["path"])
        unique = {key(ref): ref for ref in references}
        groups = {}
        for ref in unique.values():
            groups.setdefault(ref["repo_id"], []).append(ref)
        authority = self.read_authority
        authority.preparation.prepare(authority.actor)
        current = authority.preparation.contexts.current(authority.actor)
        if current is None:
            raise ContractError("SUBJECT_UNAVAILABLE", "Batch subject is unavailable", 503)
        epoch = current["context_epoch"]
        scopes = [dict(type="provider", provider=authority.state.provider, external_id=authority.state.provider),
            dict(type="user", provider=authority.state.provider, external_id=authority.actor)]
        scopes.extend(dict(type="repo", provider="cloudfile", external_id=repo)
            for repo in sorted({ref["repo_id"] for ref in references}))
        deadline = time.monotonic() + 20
        def check_deadline():
            if time.monotonic() >= deadline:
                raise ContractError("RESOURCE_UNAVAILABLE", "Resource batch deadline exceeded", 503)
        snapshots = {}
        with authority.preparation.no_refresh_scope(), ExitStack() as guards:
            # Retain all repository guards until publication, including earlier
            # committed groups. Chunk only lock acquisition (the helper caps
            # it at 16); global provider/user/repo order stays unchanged.
            for start in range(0, len(scopes), 16):
                check_deadline()
                guards.enter_context(scope_locks(authority.state.connection, scopes[start:start + 16]))
            for repo in sorted(groups):
                check_deadline()
                group = groups[repo]
                results = self.store.resolve_many_authorized(group, authority=authority,
                    lifecycle_reader=self.reader, include_tags=True, check_boundary=check_deadline)
                if len(results) != len(group):
                    raise ContractError("RESOURCE_UNAVAILABLE", "Incomplete resource batch", 503)
                snapshots.update((key(ref), result) for ref, result in zip(group, results))
                current = authority.preparation.contexts.current(authority.actor)
                if current is None or current["context_epoch"] != epoch:
                    raise ContractError("SUBJECT_UNAVAILABLE", "Batch subject changed", 503)
            check_deadline()
            # Deduplicated reads share internal snapshots, but each output slot
            # owns its nested DTO so one consumer cannot mutate another slot.
            items = [dict(reference=ref, status=404) if snapshots[key(ref)] is None else
                dict(reference=ref, status=200, snapshot=deepcopy(snapshots[key(ref)])) for ref in references]
        return dict(items=items)

    def update_attributes(self, request, *, idempotency_key=None):
        object_fields(request, ("reference", "changes", "revision"))
        value, created = self.store.write_authorized(resource_ref(request["reference"]), request["changes"],
            expected_revision=request["revision"], authority=self.write_authority, lifecycle_reader=self.reader,
            idempotency_key=idempotency_key)
        return value, created

    def replace_user_tags(self, request, *, idempotency_key=None):
        object_fields(request, ("reference", "tag_ids", "revision"))
        return self.store.replace_user_tags_authorized(resource_ref(request["reference"]), request["tag_ids"],
            expected_revision=request["revision"], authority=self.write_authority,
            lifecycle_reader=self.reader, request_id=self.request_id, idempotency_key=idempotency_key)

    def create_user_tag(self, request):
        """Create/reuse a library tag through an actual writable resource.

        Definition creation does not bind the tag or allocate a resource UID.
        Existing colors win on label reuse. Display/disable changes need their
        separate library-management authority, never this content-write path.
        """
        from ..tags.write import create_user
        from ..tags.definitions import user_definition
        from uuid import uuid4
        object_fields(request, ("reference", "value"))
        reference = resource_ref(request["reference"])
        # Validate before acquiring native/SQL resources; no caller-controlled
        # provider, namespace, tag ID, actor or cross-library scope is accepted.
        candidate = user_definition(reference["repo_id"], str(uuid4()), request["value"])
        value = {"label": candidate["label"], "color": candidate["color"]}
        def create(cursor, ref):
            evidence = self.store._validate_evidence(self.reader(cursor, ref))
            # Existing sparse state must agree with actual lifecycle. An
            # unannotated native resource is valid and remains unallocated.
            self.store._row(ref, evidence, locking=True)
            return create_user(cursor, repo_id=ref["repo_id"], value=value,
                actor=self.write_authority.actor, request_id=self.request_id)
        return self.write_authority.consume(reference, create)

    def replace_user_tag_values(self, request, *, idempotency_key=None):
        """Replace user labels atomically without a global dictionary query."""
        object_fields(request, ("reference", "values", "revision"))
        return self.store.replace_user_tags_authorized(resource_ref(request["reference"]), [],
            expected_revision=request["revision"], authority=self.write_authority,
            lifecycle_reader=self.reader, request_id=self.request_id, tag_values=request["values"],
            idempotency_key=idempotency_key)

    def update_user_tag_definition(self, request, *, if_match, idempotency_key=None):
        """Library-wide definition patch, not a resource tag binding write."""
        from ..tags.definitions import uuid_value, definition_changes
        from ..tags.write import patch_user
        object_fields(request, ("repo_id", "tag_id", "changes"))
        repo_id = uuid_value(request["repo_id"])
        tag_id = uuid_value(request["tag_id"])
        changes = definition_changes(request["changes"])
        reference = {"repo_id": repo_id, "path": "/", "kind": "dir"}
        def update(cursor, ref):
            def mutate():
                return patch_user(cursor, repo_id=ref["repo_id"], tag_id=tag_id,
                changes=changes, if_match=if_match, actor=self.tag_management.actor,
                request_id=self.request_id)
            if idempotency_key is None:
                return mutate()
            from .requests import execute
            evidence = self.store._validate_evidence(self.reader(cursor, ref))
            return execute(cursor, provider=self.tag_management.state.provider,
                actor=self.tag_management.actor, operation="tags.definition.update",
                key=idempotency_key, request=dict(repo_id=repo_id, tag_id=tag_id,
                    changes=changes, if_match=if_match), lifecycle=evidence.lifecycle_ref,
                secret=self.store.secret, mutate=mutate)
        return self.tag_management.consume(reference, update)

    def list_user_tag_definitions(self, request):
        from ..tags.catalog import list_user_definitions
        from ..tags.definitions import uuid_value
        object_fields(request, ("repo_id",), ("limit", "after"))
        reference = dict(repo_id=uuid_value(request["repo_id"]), path="/", kind="dir")
        def read(cursor, ref):
            return list_user_definitions(cursor, repo_id=ref["repo_id"],
                limit=request.get("limit", 50), after=request.get("after"))
        return self.tag_management.consume(reference, read)
