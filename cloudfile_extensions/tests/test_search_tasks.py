from unittest import TestCase
from unittest.mock import Mock

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.search.documents import resource_document
from cloudfile_extensions.search.tasks import MeilisearchTasks


class SearchTasksTest(TestCase):
    def setUp(self):
        self.client = MeilisearchTasks(endpoint="http://meilisearch:7700", index="resources", key="private")
        self.client._request = Mock()

    def test_write_receipt_is_only_task_id_not_completion(self):
        document = resource_document(dict(repo_id="11111111-1111-1111-1111-111111111111", path="/x", kind="file"), source_sequence="1")
        self.client._request.return_value = dict(taskUid=7, indexUid="resources", type="documentAdditionOrUpdate", status="enqueued")
        self.assertEqual(self.client.replace_documents([document]), 7)
        self.assertEqual(self.client._request.call_args.kwargs["status"], 202)

    def test_poll_requires_exact_task_index_type_and_identity(self):
        for field, value in (("uid", 8), ("indexUid", "other"), ("type", "documentDeletion")):
            result = dict(uid=7, indexUid="resources", type="documentAdditionOrUpdate", status="succeeded")
            result[field] = value
            self.client._request.return_value = result
            with self.assertRaises(ContractError):
                self.client.task_status(7, task_type="documentAdditionOrUpdate")

    def test_failed_task_does_not_become_success_or_expose_error(self):
        self.client._request.return_value = dict(uid=7, indexUid="resources", type="documentDeletion", status="failed", error=dict(message="private"))
        self.assertEqual(self.client.task_status(7, task_type="documentDeletion"), "failed")
