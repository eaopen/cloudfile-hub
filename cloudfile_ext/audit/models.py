# -*- coding: utf-8 -*-
"""CloudFile's own append-only audit sidecar.

seafevents' ``Activity`` table only ever holds commit-diff file/directory
operations. Repo tags are managed exclusively through Seahub's API -- there is
no WebDAV or sync-client producer for them -- so a Hub-side hook captures
*all* tag changes together with their before/after values, which is what the
review checklist's audit section requires (P2-08).

``cf_audit_event`` lives in seafile-db alongside the other cf_* tables and is
created by cloudfile-docker's bootstrap (``apply_audit_schema``), not by a
Django migration, so the model is ``managed = False``. cloudfile_ext.db_router
points it at the CF_DATABASE_ALIAS connection.
"""

import datetime
import json
import uuid

from django.db import models


def _utcnow():
    # Naive UTC, matching the timestamps seafevents writes into Activity.
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


class AuditEventManager(models.Manager):

    def append(self, object_type, object_id, operation, operator, repo_id='',
               source='api', result='success', before=None, after=None,
               source_path=None, target_path=None, failure_reason=None):
        event = self.model(
            repo_id=repo_id or '',
            object_type=object_type,
            object_id=object_id or '',
            operation=operation,
            operator=operator or '',
            source=source,
            before=json.dumps(before, ensure_ascii=False)
            if before is not None else None,
            after=json.dumps(after, ensure_ascii=False)
            if after is not None else None,
            source_path=source_path,
            target_path=target_path,
            result=result,
            failure_reason=failure_reason,
            occurred_at=_utcnow(),
        )
        event.save()
        return event


class AuditEvent(models.Model):
    repo_id = models.CharField(max_length=36, db_index=True)
    object_type = models.CharField(max_length=32)
    object_id = models.CharField(max_length=64)
    operation = models.CharField(max_length=32, db_index=True)
    operator = models.CharField(max_length=255, db_index=True)
    source = models.CharField(max_length=16, db_index=True)
    before = models.TextField(null=True)
    after = models.TextField(null=True)
    source_path = models.CharField(max_length=1000, null=True)
    target_path = models.CharField(max_length=1000, null=True)
    result = models.CharField(max_length=16, db_index=True)
    failure_reason = models.TextField(null=True)
    occurred_at = models.DateTimeField(db_index=True)

    objects = AuditEventManager()

    class Meta:
        managed = False
        db_table = 'cf_audit_event'
        app_label = 'cloudfile_ext'

    def before_dict(self):
        return json.loads(self.before) if self.before else None

    def after_dict(self):
        return json.loads(self.after) if self.after else None

    def __str__(self):
        return 'AuditEvent<id: %s, %s %s:%s by %s>' % (
            self.id, self.operation, self.object_type, self.object_id,
            self.operator)
