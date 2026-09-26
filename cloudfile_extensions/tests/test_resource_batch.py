"""Actual batch orchestration with mocked per-item reads; not native ACL proof."""
from contextlib import nullcontext
from unittest import TestCase
from unittest.mock import Mock, patch

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.resources.service import ResourceService


class ResourceBatchTest(TestCase):
    def setUp(self):
        self.service = object.__new__(ResourceService)
        self.service.read_authority = Mock(actor="employee")
        self.service.read_authority.state.provider = "directory"
        self.service.read_authority.preparation.contexts.current.return_value = {"context_epoch": "epoch"}
        self.service.resolve = Mock(side_effect=lambda value: dict(resource=value["reference"], description=""))
        self.refs = [dict(repo_id="11111111-1111-1111-1111-111111111111", path="/a", kind="file"),
            dict(repo_id="22222222-2222-2222-2222-222222222222", path="/b", kind="file")]

    def read(self):
        with patch("cloudfile_extensions.jobs.authority.scope_locks", return_value=nullcontext()):
            return self.service.batch_resolve(dict(references=self.refs))

    def test_normalizes_all_inputs_before_preparation_and_bounds_count(self):
        for values in ([], self.refs * 51, [self.refs[0], {**self.refs[1], "path": "/../bad"}]):
            with self.assertRaises(ContractError):
                self.service.batch_resolve(dict(references=values))
        self.service.read_authority.preparation.prepare.assert_not_called()

    def test_preserves_order_and_hides_denied_resource(self):
        self.service.resolve.side_effect = [dict(description=""), ContractError("ACCESS_DENIED", "hidden", 403)]
        result = self.read()["items"]
        self.assertEqual([item["reference"] for item in result], self.refs)
        self.assertEqual([item["status"] for item in result], [200, 404])
        self.assertEqual(set(result[1]), {"reference", "status"})

    def test_runtime_failure_or_epoch_change_discards_accumulated_batch(self):
        self.service.resolve.side_effect = [dict(description=""), ContractError("POLICY_UNAVAILABLE", "down", 503)]
        with self.assertRaises(ContractError):
            self.read()
        self.service.resolve.side_effect = lambda value: dict(description="")
        self.service.read_authority.preparation.contexts.current.side_effect = [
            {"context_epoch": "old"}, {"context_epoch": "new"}]
        with self.assertRaises(ContractError) as caught:
            self.read()
        self.assertEqual(caught.exception.code, "SUBJECT_UNAVAILABLE")
