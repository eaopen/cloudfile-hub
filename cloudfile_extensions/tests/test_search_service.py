"""Actual query orchestration with adapter fixtures, not native ACL proof."""
from unittest import TestCase
from unittest.mock import Mock

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.resources.service import ResourceService
from cloudfile_extensions.search.cursor import SearchCursorStore
from cloudfile_extensions.search.meilisearch import MeilisearchCandidates
from cloudfile_extensions.search.service import ResourceSearchService


class SearchServiceTest(TestCase):
    def setUp(self):
        self.repo = "11111111-1111-1111-1111-111111111111"
        self.resources = object.__new__(ResourceService)
        self.resources.read_authority = Mock(actor="employee")
        self.resources.read_authority.preparation.contexts.current.return_value = dict(context_epoch="epoch")
        self.ref = dict(repo_id=self.repo, path="/drawing", kind="file")
        self.resources.batch_resolve = Mock(return_value=dict(items=[dict(reference=self.ref, status=404)]))
        self.backend = object.__new__(MeilisearchCandidates)
        self.backend.page = Mock(return_value=dict(references=[self.ref], next_offset=1))
        self.cursors = object.__new__(SearchCursorStore)
        self.cursors.issue = Mock(return_value="opaque")
        self.versions = Mock(return_value=dict(ready=True, policy_revision="p", index_generation="i"))
        self.service = ResourceSearchService(self.resources, self.backend, self.cursors, version_reader=self.versions)

    def test_denied_candidate_is_not_returned_but_pagination_survives(self):
        result = self.service.query(dict(q="drawing", repo_id=self.repo))
        self.assertEqual(result["items"], [])
        self.assertEqual(result["next_cursor"], "opaque")
        self.resources.batch_resolve.assert_called_once_with(dict(references=[self.ref]))
        self.assertNotIn("total", result)

    def test_index_change_discards_resolved_results(self):
        self.versions.side_effect = [dict(ready=True, policy_revision="p", index_generation="i"),
            dict(ready=True, policy_revision="p", index_generation="new")]
        with self.assertRaises(ContractError):
            self.service.query(dict(q="drawing", repo_id=self.repo))
        self.cursors.issue.assert_not_called()

    def test_subject_change_discards_results(self):
        self.resources.read_authority.preparation.contexts.current.side_effect = [dict(context_epoch="old"), dict(context_epoch="new")]
        with self.assertRaises(ContractError):
            self.service.query(dict(q="drawing", repo_id=self.repo))

    def test_removed_or_disabled_tag_cannot_survive_stale_index_filter(self):
        tag = "22222222-2222-4222-8222-222222222222"
        self.resources.batch_resolve.return_value = dict(items=[dict(reference=self.ref, status=200,
            snapshot=dict(tags=[dict(tag_id=tag, enabled=False)]))])
        self.assertEqual(self.service.query(dict(q="drawing", repo_id=self.repo, tag_ids=[tag]))["items"], [])
        self.resources.batch_resolve.return_value["items"][0]["snapshot"]["tags"][0]["enabled"] = True
        self.assertEqual(len(self.service.query(dict(q="drawing", repo_id=self.repo, tag_ids=[tag]))["items"]), 1)
