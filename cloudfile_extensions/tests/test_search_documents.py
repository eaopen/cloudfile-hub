from unittest import TestCase

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.search.documents import INDEX_SETTINGS, document_key, resource_document


class SearchDocumentsTest(TestCase):
    def setUp(self):
        self.ref = dict(repo_id="11111111-1111-1111-1111-111111111111", path="/a%2Fb.prt", kind="file")

    def test_native_unannotated_file_is_searchable_without_sparse_allocation(self):
        result = resource_document(self.ref, source_sequence="1")
        self.assertEqual(result["name"], "a%2Fb.prt")
        self.assertEqual(result["description"], "")
        self.assertEqual(result["tag_ids"], [])
        self.assertIsNone(result["resource_uid"])
        self.assertEqual(INDEX_SETTINGS["displayedAttributes"], ["repo_id", "path", "kind"])

    def test_equal_content_at_different_paths_does_not_share_identity(self):
        self.assertNotEqual(document_key(self.ref), document_key({**self.ref, "path": "/b.prt"}))
        self.assertNotEqual(document_key(self.ref), document_key({**self.ref, "kind": "dir"}))

    def test_only_enabled_tags_and_no_project_or_permission_attributes(self):
        tag = dict(tag_id="22222222-2222-2222-2222-222222222222", kind="user", enabled=True,
            label="工艺", code="drawing", scope_repo_id=self.ref["repo_id"], color="#FF0000")
        annotation = dict(resource=self.ref, description="说明", uid=None, tags=[tag], local_open_type="UG12", access=dict(read=True))
        result = resource_document(self.ref, source_sequence="2", annotation=annotation)
        self.assertEqual(result["tag_labels"], ["工艺"])
        self.assertNotIn("local_open_type", result)
        self.assertNotIn("access", result)
        self.assertNotIn("color", result)
        tag["enabled"] = False
        self.assertEqual(resource_document(self.ref, source_sequence="3", annotation=annotation)["tag_ids"], [])

    def test_mismatched_annotation_cannot_be_projected(self):
        with self.assertRaises(ContractError):
            resource_document(self.ref, source_sequence="1", annotation=dict(resource={**self.ref, "path": "/other"}))
