from unittest import TestCase
from unittest.mock import Mock

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.search.tag_fanout import binding_page, binding_cutoff, global_binding_page


class TagFanoutTest(TestCase):
    def setUp(self):
        self.repo = "11111111-1111-1111-1111-111111111111"
        self.tag = "22222222-2222-2222-2222-222222222222"
        self.revision = "33333333-3333-3333-3333-333333333333"
        self.definition = (self.tag, "user", "cloudfile", "user:" + self.repo, self.tag, "图纸", "图纸", None, 1, self.repo, self.revision)
        self.uid = "44444444-4444-4444-4444-444444444444"
        self.cursor = Mock()

    def test_page_uses_indexed_uid_order_and_preserves_literal_path(self):
        row = (self.uid, self.uid, self.repo, "/a%2Fb", "file", "active")
        self.cursor.fetchall.side_effect = [(self.definition,), (("tag_id", None), ("resource_uid", None)), (row,)]
        result = binding_page(self.cursor, repo_id=self.repo, tag_id=self.tag, revision=self.revision, upper_uid=self.uid)
        self.assertEqual(result["items"][0]["reference"]["path"], "/a%2Fb")
        self.assertIsNone(result["next_uid"])
        self.assertEqual(self.cursor.execute.call_args.args[1], (self.tag, "", self.uid, 101))

    def test_definition_change_does_not_continue_stale_fanout(self):
        self.cursor.fetchall.return_value = (self.definition,)
        with self.assertRaises(ContractError) as caught:
            binding_page(self.cursor, repo_id=self.repo, tag_id=self.tag, revision=self.uid, upper_uid=self.uid)
        self.assertEqual(caught.exception.code, "SEARCH_FANOUT_CHANGED")

    def test_orphan_binding_is_not_silently_dropped(self):
        self.cursor.fetchall.side_effect = [(self.definition,), (("tag_id", None), ("resource_uid", None)), ((self.uid, None, None, None, None, None),)]
        with self.assertRaises(ContractError):
            binding_page(self.cursor, repo_id=self.repo, tag_id=self.tag, revision=self.revision, upper_uid=self.uid)

    def test_cutoff_is_explicit_and_empty_binding_set_is_distinct(self):
        self.cursor.fetchone.return_value = (self.uid,)
        self.assertEqual(binding_cutoff(self.cursor, tag_id=self.tag), self.uid)
        self.cursor.fetchone.return_value = (None,)
        self.assertIsNone(binding_cutoff(self.cursor, tag_id=self.tag))

    def test_cursor_beyond_cutoff_does_not_query(self):
        with self.assertRaises(ValueError):
            binding_page(self.cursor, repo_id=self.repo, tag_id=self.tag, revision=self.revision, upper_uid=self.revision, after=self.uid)
        self.cursor.execute.assert_not_called()

    def test_global_system_tag_scans_multiple_libraries_once(self):
        definition = (self.tag, "system", "cloudfile", "system", "drawings", "图纸", None, None, 1, None, self.revision)
        other_repo = "55555555-5555-5555-5555-555555555555"
        other_uid = "66666666-6666-6666-6666-666666666666"
        rows = ((self.uid, self.uid, self.repo, "/x", "file", "active"), (other_uid, other_uid, other_repo, "/y", "file", "active"))
        self.cursor.fetchall.side_effect = [(definition,), (("tag_id", None), ("resource_uid", None)), rows]
        page = global_binding_page(self.cursor, tag_id=self.tag, revision=self.revision, upper_uid=other_uid)
        self.assertEqual([item["reference"]["repo_id"] for item in page["items"]], [self.repo, other_repo])
        self.assertEqual(self.cursor.execute.call_count, 3)

    def test_global_scan_rejects_user_or_library_scoped_tag(self):
        self.cursor.fetchall.return_value = (self.definition,)
        with self.assertRaises(ContractError):
            global_binding_page(self.cursor, tag_id=self.tag, revision=self.revision, upper_uid=self.uid)
