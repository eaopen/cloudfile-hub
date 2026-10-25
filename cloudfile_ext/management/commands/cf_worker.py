# -*- coding: utf-8 -*-
"""CloudFile background worker.

Runs the periodic work that capabilities register: search indexing, external
source scans, audit archiving, metadata upkeep. It is not a separate service --
the cf-worker container runs this command from the same image as the
application.

Registration happens in ``CloudFileConfig.ready()``. Enterprise Directory
org/role catalog synchronization uses this worker at a default 600-second
interval. It never provisions users or GroupUser during permission checks.
Login remains the existing user membership synchronization point. With no
enabled periodic task this command exits 0 immediately.
"""

import fcntl
import logging
import os
import signal
import time

from django.core.management.base import BaseCommand, CommandError

from cloudfile_ext.registry import registry

logger = logging.getLogger(__name__)

#: How often to look for tasks that have come due.
TICK_SECONDS = 5


class Command(BaseCommand):
    help = 'Run CloudFile background tasks.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--once', action='store_true',
            help='Run every task once and exit, instead of looping.')

    def handle(self, *args, **options):
        tasks = registry.periodic_tasks

        if not tasks:
            self.stdout.write(
                'No CloudFile periodic tasks are registered; nothing to do. '
                'Enable a capability that needs one before running cf_worker.')
            return

        # One scheduler for a mounted Seafile instance, not one per web
        # process or compose replica. Docker passes a persistent /shared path.
        # Local test environments can use the /tmp default without a volume.
        path = os.environ.get('CF_WORKER_LOCK_FILE', '/tmp/cloudfile-cf-worker.lock')
        try:
            with open(path, 'a') as lock:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    self.stdout.write('CF_WORKER_ALREADY_RUNNING: skip duplicate scheduler')
                    return
                self.stdout.write('Running %d CloudFile task(s): %s' % (
                    len(tasks), ', '.join(t['name'] for t in tasks)))
                if options['once']:
                    for task in tasks:
                        self._run(task)
                    return
                self._loop(tasks)
        except OSError as error:
            raise CommandError('CF_WORKER_LOCK_UNAVAILABLE: %s' % type(error).__name__) from error

    def _run(self, task):
        started = time.monotonic()
        try:
            result = task['func']()
        except Exception:
            # One failing task does not kill the process or trigger a storm
            # of immediate retries: it runs again at its configured cadence.
            logger.exception('CloudFile task %s failed', task['name'])
            self.stderr.write('CF_TASK name=%s status=FAILED duration_ms=%d' % (
                task['name'], int((time.monotonic() - started) * 1000)))
            return
        # Only expose aggregate counts. Never log provider UIDs, credentials
        # or organization/role records returned by arbitrary task callbacks.
        counters = []
        if isinstance(result, dict):
            for key in ('entities', 'created', 'renamed', 'unchanged', 'membership_writes'):
                if type(result.get(key)) is int and result[key] >= 0:
                    counters.append('%s=%d' % (key, result[key]))
        self.stdout.write('CF_TASK name=%s status=OK duration_ms=%d%s' % (
            task['name'], int((time.monotonic() - started) * 1000),
            (' ' + ' '.join(counters)) if counters else ''))

    def _loop(self, tasks):
        stopping = {'now': False}

        def stop(signum, frame):
            stopping['now'] = True

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)

        next_run = {task['name']: 0 for task in tasks}

        while not stopping['now']:
            now = time.time()
            for task in tasks:
                if now >= next_run[task['name']]:
                    self._run(task)
                    next_run[task['name']] = now + task['interval']
            time.sleep(TICK_SECONDS)

        self.stdout.write('CloudFile worker stopped.')
