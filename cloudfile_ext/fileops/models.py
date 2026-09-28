# -*- coding: utf-8 -*-
"""Copy/move task idempotency storage (P2-06).

``cf_fileop_task`` lives in **seafile-db**, not seahub-db, for the same reason
every other cf_* table does: it is created by cloudfile-server/scripts/sql and
applied on every start, and the Hub reaches it through a second connection
(cloudfile_ext.db_router) with ``managed = False`` -- ``manage.py migrate``
must never own it.

The Hub is the only reader/writer: the write itself still goes through
``seafile_api.copy_file`` / ``move_file`` (and therefore repo-op.c). The table's
job is to make a repeated submission a no-op *before* that call is made.
"""

import time

from django.db import models

STATUS_RUNNING = 'running'
STATUS_SUCCEEDED = 'succeeded'
STATUS_PARTIAL = 'partial'
STATUS_FAILED = 'failed'

STATUS_CHOICES = (
    (STATUS_RUNNING, 'running'),
    (STATUS_SUCCEEDED, 'succeeded'),
    (STATUS_PARTIAL, 'partial'),
    (STATUS_FAILED, 'failed'),
)

OPERATION_COPY = 'copy'
OPERATION_MOVE = 'move'

OPERATION_CHOICES = (
    (OPERATION_COPY, 'copy'),
    (OPERATION_MOVE, 'move'),
)


class FileOpTaskManager(models.Manager):

    def find_by_key(self, username, idempotency_key):
        """Return the task for an intent, or None when it has not been seen.

        This is the idempotency lookup: two submissions with the same
        (username, key) must resolve to the same task, so the second one never
        reaches seafile_api.
        """
        return self.filter(username=username,
                           idempotency_key=idempotency_key).first()

    def claim(self, username, idempotency_key, operation, task_id):
        """Return (task, created) for one intent, atomically.

        ``get_or_create`` on the unique (username, idempotency_key) index is
        what survives two concurrent identical submissions: exactly one caller
        sees ``created=True`` and is allowed to start the real copy/move.
        """
        now = int(time.time())
        return self.get_or_create(
            username=username,
            idempotency_key=idempotency_key,
            defaults={
                'task_id': task_id,
                'operation': operation,
                'status': STATUS_RUNNING,
                'ctime': now,
                'mtime': now,
            },
        )

    def mark(self, task, status, detail=None):
        task.status = status
        task.detail = detail
        task.mtime = int(time.time())
        task.save(update_fields=['status', 'detail', 'mtime'])
        return task


class FileOpTask(models.Model):
    task_id = models.CharField(max_length=36, db_index=True)
    idempotency_key = models.CharField(max_length=64)
    username = models.CharField(max_length=255)
    operation = models.CharField(max_length=16, choices=OPERATION_CHOICES)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES)
    detail = models.TextField(null=True)
    ctime = models.BigIntegerField(null=True)
    mtime = models.BigIntegerField(null=True)

    objects = FileOpTaskManager()

    class Meta:
        managed = False
        db_table = 'cf_fileop_task'
        app_label = 'cloudfile_ext'
        unique_together = ('username', 'idempotency_key')

    def __str__(self):
        return '%s %s %s' % (self.username, self.operation, self.status)
