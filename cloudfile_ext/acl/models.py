# -*- coding: utf-8 -*-
"""Directory ACL storage.

``cf_dir_acl`` lives in **seafile-db**, not seahub-db: seaf-server and the Go
fileserver both have to read it to enforce ACL for WebDAV and the desktop sync
client, and neither of them connects to seahub-db.

The table is therefore created by cloudfile-server/scripts/sql, and the model
below is ``managed = False`` -- ``manage.py migrate`` must never own it.
cloudfile_ext.db_router points these models at the CF_DATABASE_ALIAS
connection.
"""

import time

from django.db import models

from cloudfile_ext.acl.resolver import (
    PERMISSION_RW, PERMISSION_R, PERMISSION_NONE, PERMISSION_INVISIBLE,
    SUBJECT_USER, SUBJECT_DEPT, SUBJECT_GROUP,
    normalize_path, path_hash,
)

SUBJECT_TYPE_CHOICES = (
    (SUBJECT_USER, 'user'),
    (SUBJECT_DEPT, 'department'),
    (SUBJECT_GROUP, 'group'),
)

PERMISSION_CHOICES = (
    (PERMISSION_RW, 'read-write'),
    (PERMISSION_R, 'read-only'),
    (PERMISSION_NONE, 'no access'),
    (PERMISSION_INVISIBLE, 'invisible'),
)


class DirACLManager(models.Manager):

    def rules_for_repo(self, repo_id):
        """Every rule in a repo, as plain dicts for the resolver.

        The whole repo is fetched in one query rather than one query per path
        level: a permission check walks every ancestor, and repos carry few
        enough rules that one round trip beats N.
        """
        rows = self.filter(repo_id=repo_id).values(
            'path', 'subject_type', 'subject', 'permission', 'inherit')
        return [dict(row) for row in rows]

    def set_rule(self, repo_id, path, subject_type, subject, permission,
                 inherit=True):
        path = normalize_path(path)
        now = int(time.time())
        obj, _created = self.update_or_create(
            repo_id=repo_id,
            path_hash=path_hash(path),
            subject_type=subject_type,
            subject=subject,
            defaults={
                'path': path,
                'permission': permission,
                'inherit': 1 if inherit else 0,
                'mtime': now,
            },
            # Only set on insert, so editing a rule keeps its original date.
            create_defaults={
                'path': path,
                'permission': permission,
                'inherit': 1 if inherit else 0,
                'ctime': now,
                'mtime': now,
            },
        )
        return obj

    def delete_rule(self, repo_id, path, subject_type, subject):
        return self.filter(
            repo_id=repo_id,
            path_hash=path_hash(path),
            subject_type=subject_type,
            subject=subject,
        ).delete()


class DirACL(models.Model):
    repo_id = models.CharField(max_length=36, db_index=True)
    path = models.CharField(max_length=1000)
    #: sha1(path); indexed instead of `path` because MySQL cannot index a
    #: 1000-character utf8mb4 column.
    path_hash = models.CharField(max_length=40)
    subject_type = models.CharField(max_length=16, choices=SUBJECT_TYPE_CHOICES)
    subject = models.CharField(max_length=255)
    permission = models.CharField(max_length=16, choices=PERMISSION_CHOICES)
    inherit = models.SmallIntegerField(default=1)
    ctime = models.BigIntegerField(null=True)
    mtime = models.BigIntegerField(null=True)

    objects = DirACLManager()

    class Meta:
        managed = False
        db_table = 'cf_dir_acl'
        app_label = 'cloudfile_ext'
        unique_together = ('repo_id', 'path_hash', 'subject_type', 'subject')

    def __str__(self):
        return '%s:%s %s:%s=%s' % (self.repo_id, self.path, self.subject_type,
                                   self.subject, self.permission)

    def save(self, *args, **kwargs):
        # Keep path and path_hash in lockstep no matter which code path writes.
        self.path = normalize_path(self.path)
        self.path_hash = path_hash(self.path)
        return super(DirACL, self).save(*args, **kwargs)


class DirAdminManager(models.Manager):
    """Manager for directory-level admin grants (delegated manage).

    Same shape as DirACL minus the permission column: a grant *is* the admin
    role, and the manage dimension has no denies (acl-semantics.md 7).
    """

    def rules_for_repo(self, repo_id):
        rows = self.filter(repo_id=repo_id).values(
            'path', 'subject_type', 'subject', 'inherit')
        return [dict(row) for row in rows]

    def set_rule(self, repo_id, path, subject_type, subject, inherit=True):
        path = normalize_path(path)
        now = int(time.time())
        obj, _created = self.update_or_create(
            repo_id=repo_id,
            path_hash=path_hash(path),
            subject_type=subject_type,
            subject=subject,
            defaults={
                'path': path,
                'inherit': 1 if inherit else 0,
                'mtime': now,
            },
            # Only set on insert, so editing a rule keeps its original date.
            create_defaults={
                'path': path,
                'inherit': 1 if inherit else 0,
                'ctime': now,
                'mtime': now,
            },
        )
        return obj

    def delete_rule(self, repo_id, path, subject_type, subject):
        return self.filter(
            repo_id=repo_id,
            path_hash=path_hash(path),
            subject_type=subject_type,
            subject=subject,
        ).delete()


class DirAdmin(models.Model):
    repo_id = models.CharField(max_length=36, db_index=True)
    path = models.CharField(max_length=1000)
    #: sha1(path); indexed instead of `path` for the same MySQL reason as
    #: cf_dir_acl.
    path_hash = models.CharField(max_length=40)
    subject_type = models.CharField(max_length=16, choices=SUBJECT_TYPE_CHOICES)
    subject = models.CharField(max_length=255)
    inherit = models.SmallIntegerField(default=1)
    ctime = models.BigIntegerField(null=True)
    mtime = models.BigIntegerField(null=True)

    objects = DirAdminManager()

    class Meta:
        managed = False
        db_table = 'cf_dir_admin'
        app_label = 'cloudfile_ext'
        unique_together = ('repo_id', 'path_hash', 'subject_type', 'subject')

    def __str__(self):
        return '%s:%s %s:%s' % (self.repo_id, self.path, self.subject_type,
                                self.subject)

    def save(self, *args, **kwargs):
        self.path = normalize_path(self.path)
        self.path_hash = path_hash(self.path)
        return super(DirAdmin, self).save(*args, **kwargs)
