"""Tag business dispatch regression source; execution deferred."""
import unittest
from unittest.mock import Mock, patch

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.resources.service import ResourceService
from cloudfile_extensions.resources.store import ResourceEvidence


class ResourceTagServiceTest(unittest.TestCase):
    def test_create_runs_inside_authority_with_lifecycle_and_fixed_actor(self):
        service = ResourceService.__new__(ResourceService)
        service.reader = Mock(return_value=ResourceEvidence("native-object"))
        service.store = Mock()
        service.store._validate_evidence.side_effect = lambda value: value
        service.write_authority = Mock(actor="business-user")
        cursor = Mock()
        service.write_authority.consume.side_effect = lambda ref, callback: callback(cursor, ref)
        service.request_id = "request-id"
        reference = dict(repo_id="11111111-1111-4111-8111-111111111111", path="/file", kind="file")
        with patch("cloudfile_extensions.tags.write.create_user", return_value=({"label": "drawing"}, True)) as create:
            self.assertEqual(service.create_user_tag(dict(reference=reference, value=dict(label=" drawing "))),
                ({"label": "drawing"}, True))
            service.reader.assert_called_once_with(cursor, reference)
            service.store._row.assert_called_once_with(reference, service.reader.return_value, locking=True)
            create.assert_called_once_with(cursor, repo_id=reference["repo_id"],
                value=dict(label="drawing", color=None), actor="business-user", request_id="request-id")
        service.store.write.assert_not_called()

    def test_reject_caller_actor_before_authority_dispatch(self):
        service = ResourceService.__new__(ResourceService)
        service.write_authority = Mock()
        with self.assertRaises(ContractError):
            service.create_user_tag(dict(reference={}, value={}, actor="other"))
        service.write_authority.consume.assert_not_called()
