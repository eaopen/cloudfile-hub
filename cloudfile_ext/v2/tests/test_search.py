"""Pure offline Search V2 checks: no CE server, database, Redis or Meili needed."""
import unittest
from uuid import uuid4

from cloudfile_ext.v2.search.documents import (INDEX_SETTINGS, InvalidIndexDocument,
                                                document_id, index_document)
from cloudfile_ext.v2.search.paging import page, SearchPageUnavailable


REPO = "a6fbc97c-1000-4000-8000-010101010101"


class IndexDocumentTests(unittest.TestCase):
    def test_native_tags_and_empty_optional_text(self):
        doc = index_document(repo_id=REPO, path="/项目A/设计/流程.pdf", kind="file",
                             size=500, mtime=100, tags=[{"key": "TAG1", "label": "工艺"},
                                                        {"key": "TAG1", "label": "工艺"}])
        self.assertEqual(doc["name"], "流程.pdf")
        self.assertEqual(doc["extension"], "pdf")
        self.assertEqual(doc["ancestor_paths"], ["/项目A", "/项目A/设计"])
        self.assertEqual(doc["tag_keys"], ["TAG1"])
        self.assertEqual(doc["tag_labels"], ["工艺"])
        self.assertEqual((doc["description"], doc["content"]), ("", ""))
        self.assertEqual(INDEX_SETTINGS["searchableAttributes"][:2], ["name", "tag_labels"])
        plain = index_document(repo_id=REPO, path="/项目AB/无标签", kind="dir")
        self.assertEqual(plain["tag_keys"], [])
        self.assertEqual(plain["extension"], "")
        self.assertNotIn("/项目A", plain["ancestor_paths"])
        self.assertNotEqual(doc["id"], plain["id"])

    def test_distinct_types_and_explicit_parsed_text(self):
        a = document_id(repo_id=REPO, path="/X", kind="dir")
        b = document_id(repo_id=REPO, path="/X", kind="file")
        self.assertNotEqual(a, b)
        doc = index_document(repo_id=REPO, path="/folder/doc.txt", kind="file",
                             description="业务文档", content="已由可信来源解析")
        self.assertEqual(doc["content"], "已由可信来源解析")
        self.assertEqual(doc["description"], "业务文档")

    def test_rejects_untrusted_path_and_malformed_tags(self):
        for path in ("/", "/A/../B", "/A//B", "/A/", "relative.txt"):
            with self.subTest(path=path), self.assertRaises(InvalidIndexDocument):
                index_document(repo_id=REPO, path=path, kind="file")
        with self.assertRaises(InvalidIndexDocument):
            index_document(repo_id=REPO, path="/A", kind="dir",
                           tags=[{"key": "", "label": "bad"}])


class PagedCandidateTests(unittest.TestCase):
    def setUp(self):
        self.rows = [dict(repo_id=REPO, path="/files/%03d.txt" % i, kind="file",
                          indexed_secret="never_return_raw_meili_data") for i in range(180)]
        self.calls = []

    def candidates(self, offset, size):
        self.calls.append((offset, size))
        return self.rows[offset:offset + size]

    @staticmethod
    def allowed(predicate):
        def resolve(references):
            return [dict(repo_id=item["repo_id"], path=item["path"], kind=item["kind"],
                         size=10) if predicate(int(item["path"].split("/")[-1][:-4]))
                    else None for item in references]
        return resolve

    def test_40_of_50_returns_without_retry(self):
        result = page(limit=50, offset=0, fetch_candidates=self.candidates,
                      resolve_authorized=self.allowed(lambda n: n < 40))
        self.assertEqual((len(result["items"]), result["next_offset"], result["candidate_queries"]), (40, 50, 1))
        self.assertEqual(self.calls, [(0, 51)])
        self.assertNotIn("indexed_secret", result["items"][0])

    def test_22_of_50_returns_without_retry(self):
        result = page(limit=50, offset=0, fetch_candidates=self.candidates,
                      resolve_authorized=self.allowed(lambda n: n < 22))
        self.assertEqual((len(result["items"]), result["next_offset"], result["candidate_queries"]), (22, 50, 1))

    def test_six_of_fifty_fetches_once_and_never_skips_lookahead(self):
        result = page(limit=50, offset=0, fetch_candidates=self.candidates,
                      resolve_authorized=self.allowed(lambda n: n < 6 or n >= 50))
        self.assertEqual(self.calls, [(0, 51), (50, 51)])
        self.assertEqual((len(result["items"]), result["next_offset"]), (50, 94))
        self.assertEqual(result["items"][-1]["path"], "/files/093.txt")
        self.assertEqual(self.rows[result["next_offset"]]["path"], "/files/094.txt")

    def test_empty_authorized_page_can_continue(self):
        result = page(limit=50, offset=0, fetch_candidates=self.candidates,
                      resolve_authorized=self.allowed(lambda n: False))
        self.assertEqual((len(result["items"]), result["next_offset"], result["candidate_queries"]), (0, 100, 2))

    def test_exhausted_candidates_end_even_if_page_short(self):
        self.rows = self.rows[:35]
        result = page(limit=50, offset=0, fetch_candidates=self.candidates,
                      resolve_authorized=self.allowed(lambda n: n < 30))
        self.assertEqual((len(result["items"]), result["next_offset"], result["candidate_queries"]), (30, None, 1))

    def test_authority_failure_or_mismatched_object_cannot_leak(self):
        with self.assertRaises(SearchPageUnavailable):
            page(limit=50, offset=0, fetch_candidates=self.candidates,
                 resolve_authorized=lambda refs: [dict(repo_id=REPO, path="/other", kind="file")] * len(refs))
        with self.assertRaises(SearchPageUnavailable):
            page(limit=50, offset=0, fetch_candidates=self.candidates,
                 resolve_authorized=lambda refs: [])
        with self.assertRaises(SearchPageUnavailable):
            page(limit=50, offset=0, fetch_candidates=lambda offset, size: [{}],
                 resolve_authorized=self.allowed(lambda n: True))


if __name__ == "__main__":
    unittest.main()
