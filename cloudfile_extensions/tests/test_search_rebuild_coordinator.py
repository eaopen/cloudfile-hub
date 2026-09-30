from contextlib import contextmanager
from unittest import TestCase
from unittest.mock import Mock

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.search.native_directory import NativeCommitDirectoryReader
from cloudfile_extensions.search.rebuild_coordinator import SearchRebuildCoordinator
from cloudfile_extensions.search.rebuild_execution import SearchRebuildExecution
from cloudfile_extensions.search.source import OwnedIndexSource


class RebuildCoordinatorTest(TestCase):
    def setUp(self):
        self.repo = "11111111-1111-4111-8111-111111111111"
        self.ref = dict(repo_id=self.repo, path="/x", kind="file")
        self.execution = Mock(spec=SearchRebuildExecution)
        self.execution.store, self.execution.client = Mock(), Mock(index="resources")
        self.execution.advance_next.return_value = dict(state="needs_page", reference=dict(repo_id=self.repo, path="/", kind="dir"), offset=0, commit_id="a" * 40, source_sequence="0")
        self.reader, self.source = Mock(spec=NativeCommitDirectoryReader), Mock(spec=OwnedIndexSource)
        self.source.worker_connection = self.execution.store.connection
        self.held = False
        @contextmanager
        def read_page(**options):
            self.assertTrue(self.held)
            yield dict(items=[self.ref], next_offset=None)
        @contextmanager
        def scope(repo):
            self.held = True
            try:
                yield object()
            finally:
                self.held = False
        self.reader.read_page.side_effect = read_page
        self.source.scope.side_effect = scope
        self.source.read.return_value = dict(resource=self.ref, uid=None, description="", tags=[])
        self.coordinator = SearchRebuildCoordinator(self.execution, self.reader, self.source)

    def test_complete_protected_projection_is_frozen_without_dispatch(self):
        result = self.coordinator.advance(generation="g1", repo_id=self.repo)
        self.assertEqual(result["state"], "page_frozen")
        self.assertFalse(self.held)
        self.execution.store.freeze.assert_called_once()
        self.assertEqual(self.execution.store.freeze.call_args.kwargs["documents"][0]["resource_uid"], None)
        self.execution.client.replace_documents.assert_not_called()

    def test_projection_failure_does_not_freeze_or_publish(self):
        self.source.read.side_effect = ContractError("SEARCH_REBUILD_PENDING", "Changed", 503)
        with self.assertRaises(ContractError):
            self.coordinator.advance(generation="g1", repo_id=self.repo)
        self.execution.store.freeze.assert_not_called()
        self.assertFalse(self.held)

    def test_existing_task_does_not_enumerate_again(self):
        self.execution.advance_next.return_value = dict(state="task_pending")
        self.assertEqual(self.coordinator.advance(generation="g1", repo_id=self.repo)["state"], "task_pending")
        self.reader.read_page.assert_not_called()
