from unittest import TestCase
from unittest.mock import Mock

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.search.tag_fanout import binding_page


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
        result = binding_page(self.cursor, repo_id=self.repo, tag_id=self.tag, revision=self.revision)
        self.assertEqual(result["items"][0]["reference"]["path"], "/a%2Fb")
        self.assertIsNone(result["next_uid"])
        self.assertEqual(self.cursor.execute.call_args.args[1], (self.tag, "", 101))

    def test_definition_change_does_not_continue_stale_fanout(self):
        self.cursor.fetchall.return_value = (self.definition,)
        with self.assertRaises(ContractError) as caught:
            binding_page(self.cursor, repo_id=self.repo, tag_id=self.tag, revision=self.uid)
        self.assertEqual(caught.exception.code, "SEARCH_FANOUT_CHANGED")

    def test_orphan_binding_is_not_silently_dropped(self):
        self.cursor.fetchall.side_effect = [(self.definition,), (("tag_id", None), ("resource_uid", None)), ((self.uid, None, None, None, None, None),)]
        with self.assertRaises(ContractError):
            binding_page(self.cursor, repo_id=self.repo, tag_id=self.tag, revision=self.revision)
