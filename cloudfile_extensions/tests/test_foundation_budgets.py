"""Real report IO boundaries and diagnostics that cannot alter task outcomes."""
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.jobs.worker import Handler, JobResult, JobWorker
from cloudfile_extensions.migration.dry_run import ImportDryRun
from cloudfile_extensions.migration.scan_limits import ScanLimits
from cloudfile_extensions.jobs.runtime import configured_handlers


class ScanBudgetTests(unittest.TestCase):
    def run_scan(self, limits=None, clock=None, content_hash=True):
        self.source = tempfile.TemporaryDirectory()
        self.reports = tempfile.TemporaryDirectory()
        self.addCleanup(self.source.cleanup)
        self.addCleanup(self.reports.cleanup)
        Path(self.source.name, 'one').write_bytes(b'abc')
        Path(self.source.name, 'two').write_bytes(b'def')
        self.execution = Mock()
        self.execution.lease_seconds = 30
        self.execution.claim = SimpleNamespace(job_id=str(uuid4()), epoch=1,
            scope={'type': 'repo'}, request={'source_id': 'source', 'content_hash': content_hash})
        options = dict(sources={'source': self.source.name}, report_root=self.reports.name,
                       limits=limits or ScanLimits())
        if clock is not None:
            options['clock'] = clock
        return ImportDryRun(**options)(self.execution)

    def test_report_metadata_matches_exact_published_bytes(self):
        result = self.run_scan()
        summary = self.execution.checkpoint.call_args.kwargs['value']
        data = Path(self.reports.name, result.result_ref.split(':', 1)[1]).read_bytes()
        self.assertEqual(summary['report_sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(summary['report_bytes'], len(data))
        self.assertEqual(summary['schema_version'], 1)
        self.assertEqual(summary['verification_scope'], 'content_hash')
        self.assertFalse(summary['import_verified'])
        self.assertFalse(summary['source_snapshot_verified'])
        self.assertNotIn(self.source.name, json.dumps(summary))
        self.assertEqual(summary['files'], 2)

    def test_entry_limit_keeps_partial_evidence_and_originals(self):
        with self.assertRaises(ContractError) as error:
            self.run_scan(ScanLimits(maximum_entries=1))
        self.assertEqual(error.exception.code, 'IMPORT_ENTRY_LIMIT')
        data = next(Path(self.reports.name).iterdir()).read_text().splitlines()
        self.assertEqual(len(data), 1)
        self.assertEqual(Path(self.source.name, 'two').read_bytes(), b'def')
        self.assertFalse(any(c.kwargs['step'] == 'scan-complete' for c in self.execution.checkpoint.call_args_list))

    def test_report_limit_does_not_publish_truncated_success(self):
        with self.assertRaises(ContractError) as error:
            self.run_scan(ScanLimits(maximum_report_bytes=1))
        self.assertEqual(error.exception.code, 'IMPORT_REPORT_LIMIT')
        self.assertEqual(next(Path(self.reports.name).iterdir()).stat().st_size, 0)

    def test_space_reserve_checked_before_creating_report(self):
        with patch('cloudfile_extensions.migration.dry_run.os.fstatvfs',
                   return_value=SimpleNamespace(f_bavail=0, f_frsize=4096)):
            with self.assertRaises(ContractError) as error:
                self.run_scan()
        self.assertEqual(error.exception.code, 'IMPORT_REPORT_SPACE_LOW')
        self.assertEqual(list(Path(self.reports.name).iterdir()), [])

    def test_deadline_checked_while_hashing_not_only_between_files(self):
        # Admit the report and first entry; expire inside the content read loop.
        clock = Mock(side_effect=[0, 0, 0, 0, 0, 2])
        with self.assertRaises(ContractError) as error:
            self.run_scan(ScanLimits(maximum_seconds=1), clock=clock)
        self.assertEqual(error.exception.code, 'IMPORT_SCAN_TIMEOUT')

    def test_trusted_configuration_rejects_unbounded_and_boolean_limits(self):
        for value in (0, -1, True, 100000001):
            with self.assertRaises(ValueError):
                ScanLimits(maximum_entries=value)
        env = {'CLOUDFILE_IMPORT_SOURCES': '{"source":"/source"}',
               'CLOUDFILE_IMPORT_REPORT_ROOT': '/reports'}
        for raw in ('', '0', '-1', '1.0', 'true', '100000001'):
            with self.assertRaises(ValueError):
                configured_handlers(dict(env, CLOUDFILE_IMPORT_SCAN_MAXIMUM_ENTRIES=raw))
        handler = configured_handlers(dict(env, CLOUDFILE_IMPORT_SCAN_MAXIMUM_ENTRIES='5'))
        self.assertEqual(handler['migration.scan'].execute.limits.maximum_entries, 5)


class WorkerDiagnosticTests(unittest.TestCase):
    def worker(self, execute, observe):
        self.store = Mock()
        self.store.claim.return_value = SimpleNamespace(job_id=str(uuid4()), kind='migration.scan', epoch=3)
        self.store.get.return_value = dict(barrier_active=False, checkpoint={'secret': 'private'})
        return JobWorker(self.store, owner='test', handlers={'migration.scan': Handler(execute)}, observe=observe)

    def test_success_only_after_store_complete_and_payload_is_not_logged(self):
        messages = []
        worker = self.worker(lambda execution: JobResult(), messages.append)
        worker.run_once()
        self.assertEqual([m['state'] for m in messages], ['job_started', 'job_checkpoint', 'job_succeeded'])
        self.assertNotIn('private', repr(messages))
        self.assertEqual(messages[-1]['lease_epoch'], '3')
        self.store.complete.assert_called_once()

    def test_sink_failure_cannot_turn_completed_task_into_failure(self):
        observer = Mock(side_effect=OSError('broken pipe'))
        worker = self.worker(lambda execution: JobResult(), observer)
        worker.run_once()
        self.store.complete.assert_called_once()
        self.store.fail.assert_not_called()

    def test_unknown_completion_never_emits_success_or_exception_text(self):
        messages = []
        worker = self.worker(lambda execution: JobResult(), messages.append)
        self.store.complete.side_effect = RuntimeError('password=private')
        self.store.fail.side_effect = ContractError('WORKER_LEASE_LOST', 'lost', 409)
        worker.run_once()
        self.assertEqual(messages[-1]['state'], 'job_lease_lost')
        self.assertNotIn('private', repr(messages))
        self.assertNotIn('job_succeeded', repr(messages))
