"""Dedicated single-thread worker; only deployment-registered handlers may run.

Startup checks schema without applying DDL. A lost DB connection terminates this
process so the supervisor can restart it; fencing, not reconnection, recovers work.
"""

import argparse
import json
import os
import signal
import sys
import threading
from uuid import uuid4

from ..migration.dry_run import ImportDryRun
from ..migration.scan_limits import ScanLimits
from ..migration.stage import ImportStage
from ..migration.working_copy import WorkingCopyBuilder
from ..migration.verify_copy import WorkingCopyVerifier
from ..migration.verify_stage import ImportVerifyStage
from ..schema.runner import SchemaRunner
from .store import JobStore
from .worker import Handler, JobWorker


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate worker configuration key")
        result[key] = value
    return result


def configured_handlers(environment):
    raw = environment.get("CLOUDFILE_IMPORT_SOURCES", "")
    if not isinstance(raw, str) or len(raw.encode()) > 65536:
        raise ValueError("invalid registered source configuration")
    sources = json.loads(raw, object_pairs_hook=_unique_object)
    if not isinstance(sources, dict) or not 1 <= len(sources) <= 64:
        raise ValueError("registered source configuration is required")
    # No import string, shell command or handler path is accepted from the job or
    # environment. Native mutations remain unavailable until their guard exists.
    handlers = {"migration.scan": Handler(ImportDryRun(
        sources=sources, report_root=environment.get("CLOUDFILE_IMPORT_REPORT_ROOT", ""),
        limits=ScanLimits.from_environment(environment)))}
    work_root = environment.get("CLOUDFILE_IMPORT_WORK_ROOT")
    if work_root is not None:
        handlers["migration.stage"] = Handler(ImportStage(builder=WorkingCopyBuilder(
            sources=sources, work_root=work_root)))
        handlers["migration.verify-copy"] = Handler(ImportVerifyStage(
            verifier=WorkingCopyVerifier(work_root=work_root)))
    return handlers


def connect_database(environment):
    import MySQLdb
    required = ("CLOUDFILE_DB_HOST", "CLOUDFILE_DB_USER", "CLOUDFILE_DB_NAME")
    if not all(environment.get(key) for key in required):
        raise ValueError("explicit worker database configuration is required")
    port = int(environment.get("CLOUDFILE_DB_PORT", "3306"))
    if not 1 <= port <= 65535:
        raise ValueError("invalid database port")
    return MySQLdb.connect(host=environment[required[0]], user=environment[required[1]],
                          database=environment[required[2]], port=port,
                          password=environment.get("CLOUDFILE_DB_PASSWORD", ""),
                          charset="utf8mb4", autocommit=True, connect_timeout=5,
                          read_timeout=10, write_timeout=10)


def run_loop(worker, stop, *, poll_seconds=2, once=False, emit=lambda value: None):
    if type(poll_seconds) is not int or not 1 <= poll_seconds <= 30 or type(once) is not bool:
        raise ValueError("invalid worker polling configuration")
    processed = 0
    emit({"state": "ready"})
    while not stop.is_set():
        job_id = worker.run_once()
        if job_id is not None:
            processed += 1
            # Processed is not succeeded: handler failure is recorded by JobWorker.
            emit({"state": "job_processed", "job_id": job_id})
        if once:
            break
        if job_id is None:
            stop.wait(poll_seconds)
    emit({"state": "stopped"})
    return processed


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run registered CloudFile background handlers")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--poll-seconds", type=int, default=2)
    parser.add_argument("--lease-seconds", type=int, default=30)
    arguments = parser.parse_args(argv)
    connection = None
    previous_signals = {}
    try:
        if not 1 <= arguments.poll_seconds <= 30 or not 1 <= arguments.lease_seconds <= 300:
            raise ValueError("invalid worker limits")
        handlers = configured_handlers(os.environ)
        connection = connect_database(os.environ)
        SchemaRunner(connection).require_current()
        worker = JobWorker(JobStore(connection), owner="worker-" + uuid4().hex,
                           handlers=handlers, lease_seconds=arguments.lease_seconds,
                           observe=lambda value: print(json.dumps(value), flush=True))
        stop = threading.Event()
        # Finish the active handler before shutdown. A supervisor-enforced kill
        # leaves a recoverable leased attempt and never releases its barrier.
        for number in (signal.SIGTERM, signal.SIGINT):
            previous_signals[number] = signal.signal(number, lambda *_: stop.set())
        run_loop(worker, stop, poll_seconds=arguments.poll_seconds, once=arguments.once,
                 emit=lambda value: print(json.dumps(value), flush=True))
        return 0
    except Exception:
        # SQL/connection exceptions can embed credentials; never log their text.
        print("CloudFile worker failed; check configuration, schema and worker state", file=sys.stderr)
        return 1
    finally:
        for number, handler in previous_signals.items():
            signal.signal(number, handler)
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
