# -*- coding: utf-8 -*-
"""CloudFile background worker.

Runs the periodic work that capabilities register: search indexing, external
source scans, audit archiving, metadata upkeep. It is not a separate service --
the cf-worker container runs this command from the same image as the
application.

SSO registers its directory-sync task when enabled; P2 and later capabilities
can register their work in the same way. With no enabled task the command exits
immediately, which is why the compose service sits behind the `worker` profile.
"""

import logging
import signal
import time

from django.core.management.base import BaseCommand

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

        self.stdout.write('Running %d CloudFile task(s): %s' % (
            len(tasks), ', '.join(t['name'] for t in tasks)))

        if options['once']:
            for task in tasks:
                self._run(task)
            return

        self._loop(tasks)

    def _run(self, task):
        try:
            task['func']()
        except Exception:
            # One failing task must not take the worker down with it; the next
            # tick retries.
            logger.exception('CloudFile task %s failed', task['name'])

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
