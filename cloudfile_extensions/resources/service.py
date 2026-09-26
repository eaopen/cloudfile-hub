"""Request-scoped attributes/tag domain consumer; no URL registration.

Native lifecycle reader remains a required trusted data-plane adapter, not a
request field. Strong revisions do not themselves prove authorization.
"""
from ..authorization.read import ContentReadAuthority, ContentMetadataWriteAuthority
from ..common.errors import ContractError
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

    def update_attributes(self, request):
        object_fields(request, ("reference", "changes", "revision"))
        value, created = self.store.write_authorized(resource_ref(request["reference"]), request["changes"],
            expected_revision=request["revision"], authority=self.write_authority, lifecycle_reader=self.reader)
        return value, created

    def replace_user_tags(self, request):
        object_fields(request, ("reference", "tag_ids", "revision"))
        return self.store.replace_user_tags_authorized(resource_ref(request["reference"]), request["tag_ids"],
            expected_revision=request["revision"], authority=self.write_authority,
            lifecycle_reader=self.reader, request_id=self.request_id)
