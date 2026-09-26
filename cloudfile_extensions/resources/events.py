"""ResourceStore mutation adapter for actual transactional audit/outbox facts."""
from datetime import datetime, timezone
from uuid import uuid4

from ..common.errors import ContractError
from ..common.validation import identifier, object_fields
from ..events.outbox import EventWriter


class ResourceMutationEvents:
    def __init__(self, *, actor, request_id):
        identifier(actor, maximum=225)
        identifier(request_id)
        self.actor, self.request_id = actor, request_id
        self.writer = EventWriter()

    def __call__(self, cursor, value):
        object_fields(value, ("action", "actor_user_id", "resource_uid", "repo_id", "path", "revision"))
        if value["actor_user_id"] != self.actor or value["action"] != "resource.attributes.updated":
            raise ContractError("ACCESS_DENIED", "Resource event does not match authenticated operation", 403)
        event = dict(value, event_id=str(uuid4()), request_id=self.request_id,
            occurred_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            actor_kind="user", source="hub", result="succeeded")
        return self.writer.append(cursor, event)
