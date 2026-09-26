from datetime import datetime, timezone
from uuid import uuid4
from unittest import TestCase
from unittest.mock import Mock

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.events.outbox import EventClaim
from cloudfile_extensions.search.projection import AttributeSearchProjection


class AttributeSearchProjectionTest(TestCase):
    def setUp(self):
        self.ref = dict(repo_id="11111111-1111-4111-8111-111111111111", path="/literal%2Fname", kind="dir")
        self.uid, event_id = str(uuid4()), str(uuid4())
        payload = dict(schema_version=1, event_id=event_id, sequence="9", stream="repo." + self.ref["repo_id"],
            occurred_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), request_id="request", actor_user_id="employee",
            actor_kind="user", source="hub", result="succeeded", action="resource.attributes.updated",
            repo_id=self.ref["repo_id"], path=self.ref["path"], resource_uid=self.uid, revision="revision")
        self.claim = EventClaim(event_id, "search", "worker", 1, payload)
        self.reader = Mock(return_value=dict(resource=self.ref, uid=self.uid, description="说明", tags=[]))
        self.projector = AttributeSearchProjection(snapshot_reader=self.reader)

    def test_actual_directory_kind_and_literal_percent_are_preserved(self):
        steps = self.projector.plan(self.claim)
        self.assertEqual(steps[0]["operation"], "replace")
        document = steps[0]["payload"][0]
        self.assertEqual(document["kind"], "dir")
        self.assertEqual(document["path"], "/literal%2Fname")
        self.assertEqual(document["source_sequence"], "9")

    def test_recreated_resource_does_not_index_old_uid(self):
        self.reader.return_value["uid"] = str(uuid4())
        with self.assertRaises(ContractError):
            self.projector.plan(self.claim)

    def test_definition_fanout_is_not_treated_as_single_resource_update(self):
        self.claim.payload["action"] = "tags.definition.updated"
        with self.assertRaises(ContractError):
            self.projector.plan(self.claim)
        self.reader.assert_not_called()
