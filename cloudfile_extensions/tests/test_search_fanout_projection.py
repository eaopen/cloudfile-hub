from unittest import TestCase
from unittest.mock import Mock, patch

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.search.fanout_projection import project_binding_page


class FanoutProjectionTest(TestCase):
    def setUp(self):
        self.ref = dict(repo_id="11111111-1111-1111-1111-111111111111", path="/drawing", kind="file")
        self.uid = "22222222-2222-2222-2222-222222222222"
        self.revision = "33333333-3333-3333-3333-333333333333"
        self.cursor = Mock()
        self.cursor.fetchone.return_value = (self.revision,)
        self.reader = Mock(return_value=dict(resource=self.ref, uid=self.uid, description="说明", tags=[]))
        self.page = dict(items=[dict(reference=self.ref, resource_uid=self.uid)], next_uid=None)

    def project(self):
        with patch("cloudfile_extensions.search.fanout_projection.binding_page", return_value=self.page):
            return project_binding_page(self.cursor, repo_id=self.ref["repo_id"], tag_id=self.uid, revision=self.revision,
                upper_uid=self.uid, after=None, source_sequence="9", snapshot_reader=self.reader)

    def test_exact_current_resource_is_projected_using_owned_cursor(self):
        result = self.project()
        self.assertEqual(result["documents"][0]["description"], "说明")
        self.reader.assert_called_once_with(self.cursor, self.ref)

    def test_recreated_uid_discards_entire_page(self):
        self.reader.return_value["uid"] = self.revision
        with self.assertRaises(ContractError):
            self.project()

    def test_definition_change_after_native_reads_discards_page(self):
        self.cursor.fetchone.return_value = (self.uid,)
        with self.assertRaises(ContractError) as caught:
            self.project()
        self.assertEqual(caught.exception.code, "SEARCH_FANOUT_CHANGED")
