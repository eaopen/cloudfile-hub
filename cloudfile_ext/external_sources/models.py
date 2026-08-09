# -*- coding: utf-8 -*-
"""External source registration and grants.

Both tables live in **seafile-db** and are created by cloudfile-server/
scripts/sql, so the models are ``managed = False`` -- see
cloudfile_ext.db_router. Unlike cf_dir_acl nothing below the Hub reads them;
they are there because that is the one schema mechanism for cf_* tables, and a
second home in seahub-db would mean a Django migration history to carry across
every upstream merge in exchange for nothing.
"""

import hashlib
import json
import time
import uuid

from django.db import models

# Re-exported for callers that already hold a models import. The definitions
# live in authz.py so that the authorisation rule stays importable without
# Django -- see that module's docstring.
from cloudfile_ext.external_sources.authz import (  # noqa: F401
    PERMISSION_R, SUBJECT_GROUP, SUBJECT_USER, VALID_PERMISSIONS,
    VALID_SUBJECT_TYPES,
)


class ExternalSourceManager(models.Manager):

    def create_source(self, name, source_type, root_path):
        """Register a source, allocating its synthetic repo id.

        The repo id is generated here rather than by a caller so there is one
        place that decides what it is. It matches no real library: it exists so
        cf_dir_acl rules can be written against this source's subdirectories
        with no new code, and so the shadow layer has an id to present.
        """
        now = int(time.time())
        return self.create(
            repo_id=str(uuid.uuid4()),
            name=name,
            source_type=source_type,
            root_path=root_path,
            enabled=1,
            ctime=now,
            mtime=now,
        )

    def enabled_sources(self):
        return self.filter(enabled=1).order_by('name')

    def by_repo_id(self, repo_id):
        return self.filter(repo_id=repo_id).first()


class ExternalSource(models.Model):
    #: Synthetic UUID, not a foreign key into Repo. Nothing may pass this to
    #: seafile_api expecting a library to come back.
    repo_id = models.CharField(max_length=36, unique=True)
    name = models.CharField(max_length=255, unique=True)
    source_type = models.CharField(max_length=32)
    #: Container path. Must resolve under CF_EXTERNAL_SOURCES_ROOTS -- checked
    #: on every access, not only here, because the share is writable by people
    #: who can add symlinks after registration.
    root_path = models.CharField(max_length=1000)
    enabled = models.SmallIntegerField(default=1)
    ctime = models.BigIntegerField(null=True)
    mtime = models.BigIntegerField(null=True)

    objects = ExternalSourceManager()

    class Meta:
        managed = False
        db_table = 'cf_external_source'
        app_label = 'cloudfile_ext'

    def __str__(self):
        return '%s(%s) -> %s' % (self.name, self.source_type, self.root_path)


class ExternalSourceGrantManager(models.Manager):

    def grant(self, source_id, subject_type, subject,
              permission=PERMISSION_R):
        obj, _created = self.update_or_create(
            source_id=source_id,
            subject_type=subject_type,
            subject=subject,
            defaults={'permission': permission},
            create_defaults={
                'permission': permission,
                'ctime': int(time.time()),
            },
        )
        return obj

    def revoke(self, source_id, subject_type, subject):
        return self.filter(source_id=source_id, subject_type=subject_type,
                           subject=subject).delete()

    def for_source(self, source_id):
        return self.filter(source_id=source_id).order_by('subject_type',
                                                         'subject')


class ExternalSourceGrant(models.Model):
    #: Plain integer, not a ForeignKey: cf_* tables carry ids as columns
    #: because they span databases (see cloudfile_ext.db_router), so a relation
    #: here would be one Django refuses to traverse anyway.
    source_id = models.BigIntegerField(db_index=True)
    subject_type = models.CharField(max_length=16)
    subject = models.CharField(max_length=255)
    permission = models.CharField(max_length=16)
    ctime = models.BigIntegerField(null=True)

    objects = ExternalSourceGrantManager()

    class Meta:
        managed = False
        db_table = 'cf_external_source_grant'
        app_label = 'cloudfile_ext'
        unique_together = ('source_id', 'subject_type', 'subject')

    def __str__(self):
        return '%s:%s=%s' % (self.subject_type, self.subject, self.permission)


class ExternalScanStateManager(models.Manager):

    def get_state(self, source_id):
        return self.filter(source_id=source_id).first()

    def save_state(self, source_id, cursor_path, status, detail=''):
        now = int(time.time())
        obj, _created = self.update_or_create(
            source_id=source_id,
            defaults={
                'cursor_path': cursor_path,
                'last_run': now,
                'status': status,
                'detail': detail[:2000],
            },
        )
        return obj


class ExternalScanState(models.Model):
    source_id = models.BigIntegerField(unique=True)
    cursor_path = models.CharField(max_length=1000, null=True)
    last_run = models.BigIntegerField(null=True)
    status = models.CharField(max_length=16)
    detail = models.TextField(null=True)

    objects = ExternalScanStateManager()

    class Meta:
        managed = False
        db_table = 'cf_external_scan_state'
        app_label = 'cloudfile_ext'


class ExternalOverlayManager(models.Manager):

    @staticmethod
    def path_hash(path):
        return hashlib.sha1(path.encode('utf-8')).hexdigest()

    def get_overlay(self, source_id, path):
        return self.filter(source_id=source_id,
                           path_hash=self.path_hash(path)).first()

    def update_overlay(self, source_id, path, metadata=None, tags=None):
        now = int(time.time())
        values = {'path': path, 'mtime': now}
        if metadata is not None:
            values['metadata'] = json.dumps(metadata, ensure_ascii=False,
                                            sort_keys=True)
        if tags is not None:
            values['tags'] = json.dumps(tags, ensure_ascii=False)
        obj, created = self.get_or_create(
            source_id=source_id, path_hash=self.path_hash(path),
            defaults=dict(values, ctime=now),
        )
        if not created:
            for key, value in values.items():
                setattr(obj, key, value)
            obj.save(update_fields=list(values))
        return obj


class ExternalOverlay(models.Model):
    source_id = models.BigIntegerField(db_index=True)
    path = models.CharField(max_length=1000)
    path_hash = models.CharField(max_length=40)
    metadata = models.TextField(null=True)
    tags = models.TextField(null=True)
    ctime = models.BigIntegerField(null=True)
    mtime = models.BigIntegerField(null=True)

    objects = ExternalOverlayManager()

    class Meta:
        managed = False
        db_table = 'cf_external_overlay'
        app_label = 'cloudfile_ext'
        unique_together = ('source_id', 'path_hash')
