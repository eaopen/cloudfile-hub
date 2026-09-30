"""Private transport fixtures; not Meilisearch or live ACL integration evidence."""
import io
import json
from email.message import Message
from unittest import TestCase
from unittest.mock import Mock

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.search.meilisearch import MeilisearchCandidates


class SearchCandidatesTest(TestCase):
    repo = "11111111-1111-1111-1111-111111111111"

    def setUp(self):
        self.backend = MeilisearchCandidates(endpoint="http://meilisearch:7700", index="resources", key="private-key")
        self.backend.opener = Mock()

    def response(self, document):
        response = io.BytesIO(json.dumps(document).encode())
        response.status = 200
        response.headers = Message()
        response.headers["Content-Type"] = "application/json"
        self.backend.opener.open.return_value = response

    def test_only_references_escape_private_index(self):
        self.response(dict(hits=[dict(repo_id=self.repo, path="/literal%2Fname", kind="file")], estimatedTotalHits=999))
        result = self.backend.page(q="drawing", repo_id=self.repo, limit=1)
        self.assertEqual(set(result), {"references", "next_offset"})
        self.assertEqual(result["references"][0]["path"], "/literal%2Fname")
        request = self.backend.opener.open.call_args.args[0]
        payload = json.loads(request.data)
        self.assertEqual(payload["attributesToRetrieve"], ["repo_id", "path", "kind"])
        self.assertNotIn("facets", payload)

    def test_wrong_repository_and_unexpected_hit_fields_fail_whole_page(self):
        for hit in (dict(repo_id="22222222-2222-2222-2222-222222222222", path="/x", kind="file"),
                dict(repo_id=self.repo, path="/x", kind="file", allow=True)):
            self.response(dict(hits=[hit]))
            with self.assertRaises(ContractError) as caught:
                self.backend.page(q="x", repo_id=self.repo)
            self.assertEqual(caught.exception.code, "SEARCH_UNAVAILABLE")

    def test_directory_and_kind_filters_are_sent_before_pagination(self):
        path = '/中文/%2F+_"'
        self.response(dict(hits=[dict(repo_id=self.repo, path=path + '/drawing', kind='file')]))
        self.backend.page(q='drawing', repo_id=self.repo, path=path, kind='file')
        payload = json.loads(self.backend.opener.open.call_args.args[0].data)
        self.assertIn('dirs = ' + json.dumps(path, ensure_ascii=False), payload['filter'])
        self.assertIn('kind = "file"', payload['filter'])

    def test_sibling_prefix_and_wrong_kind_cannot_escape_scope(self):
        for path, kind in (('/ab/drawing', 'file'), ('/a/drawing', 'dir'), ('/a', 'dir')):
            self.response(dict(hits=[dict(repo_id=self.repo, path=path, kind=kind)]))
            with self.assertRaises(ContractError):
                self.backend.page(q='drawing', repo_id=self.repo, path='/a', kind='file')

    def test_bad_input_never_calls_network(self):
        for q in ("", "x" * 513, "\ud800"):
            with self.assertRaises(ContractError):
                self.backend.page(q=q, repo_id=self.repo)
        self.backend.opener.open.assert_not_called()
