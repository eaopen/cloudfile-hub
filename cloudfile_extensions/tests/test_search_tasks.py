from unittest import TestCase
from unittest.mock import Mock

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.search.documents import resource_document
from cloudfile_extensions.search.documents import INDEX_SETTINGS
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

    def test_create_and_configure_have_fixed_identity_and_receipt_types(self):
        self.client._request.return_value = dict(taskUid=8, indexUid="resources", type="indexCreation", status="enqueued")
        self.assertEqual(self.client.create_index(), 8)
        self.client._request.assert_called_with("http://meilisearch:7700/indexes", method="POST", data=dict(uid="resources", primaryKey="id"), status=202)
        self.client._request.return_value = dict(taskUid=9, indexUid="resources", type="settingsUpdate", status="enqueued")
        self.assertEqual(self.client.configure_index(), 9)
        self.client._request.assert_called_with("http://meilisearch:7700/indexes/resources/settings", method="PATCH", data=INDEX_SETTINGS, status=202)

    def test_current_configuration_rejects_wildcards_and_changed_ranking_order(self):
        self.client._request.side_effect = [dict(uid="resources", primaryKey="id"), dict(INDEX_SETTINGS)]
        self.client.require_configuration()
        for key, value in (("displayedAttributes", ["*"]), ("searchableAttributes", list(reversed(INDEX_SETTINGS["searchableAttributes"]))), ("filterableAttributes", ["repo_id", "kind", "kind"])):
            settings = dict(INDEX_SETTINGS)
            settings[key] = value
            self.client._request.side_effect = [dict(uid="resources", primaryKey="id"), settings]
            with self.assertRaises(ContractError):
                self.client.require_configuration()

    def test_initialization_tasks_use_exact_index_and_task_type(self):
        for task_type in ("indexCreation", "settingsUpdate"):
            self.client._request.side_effect = None
            self.client._request.return_value = dict(uid=8, indexUid="resources", type=task_type, status="succeeded")
            self.assertEqual(self.client.task_status(8, task_type=task_type), "succeeded")
            with self.assertRaises(ContractError):
                self.client.task_status(8, task_type="documentDeletion")
