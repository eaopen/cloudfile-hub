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

from django.db import connections, models, transaction

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


class DirACLRevision(models.Model):
    """Monotonic revision of one repository's authoritative ACL set.

    The row lives beside ``cf_dir_acl`` in seafile-db.  A consumer may cache a
    verdict only while this value remains unchanged; every rule mutation is in
    the same transaction as its revision bump.
    """
    repo_id = models.CharField(max_length=36, primary_key=True)
    revision = models.BigIntegerField()
    updated_at = models.BigIntegerField()

    class Meta:
        managed = False
        db_table = 'cf_dir_acl_repo_revision'
        app_label = 'cloudfile_ext'


class DirACLManager(models.Manager):

    def _bump_revision(self, repo_id, now):
        """Atomically advance and return the repository ACL revision.

        MySQL is the production backend.  The SQLite form keeps the developer
        schema usable without weakening the one-statement upsert guarantee.
        """
        alias = self.db
        connection = connections[alias]
        if connection.vendor == 'mysql':
            query = (
                'INSERT INTO cf_dir_acl_repo_revision '
                '(repo_id, revision, updated_at) VALUES (%s, %s, %s) '
                'ON DUPLICATE KEY UPDATE revision = revision + 1, '
                'updated_at = VALUES(updated_at)'
            )
        elif connection.vendor == 'sqlite':
            query = (
                'INSERT INTO cf_dir_acl_repo_revision '
                '(repo_id, revision, updated_at) VALUES (%s, %s, %s) '
                'ON CONFLICT(repo_id) DO UPDATE SET revision = revision + 1, '
                'updated_at = excluded.updated_at'
            )
        else:
            # CloudFile ships MySQL and SQLite schema variants only.  Do not
            # silently use a non-atomic read-modify-write for another backend.
            raise RuntimeError('unsupported CloudFile ACL database backend')

        with connection.cursor() as cursor:
            # The absence of a row is logical bootstrap revision 1.  The
            # write being committed here is therefore revision 2, matching
            # the C authority's bootstrap value and the shared contract.
            cursor.execute(query, [repo_id, 2, now])
            cursor.execute(
                'SELECT revision FROM cf_dir_acl_repo_revision '
                'WHERE repo_id = %s', [repo_id])
            return int(cursor.fetchone()[0])

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
        with transaction.atomic(using=self.db):
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
            self._bump_revision(repo_id, now)
        return obj

    def delete_rule(self, repo_id, path, subject_type, subject):
        with transaction.atomic(using=self.db):
            result = self.filter(
                repo_id=repo_id,
                path_hash=path_hash(path),
                subject_type=subject_type,
                subject=subject,
            ).delete()
            self._bump_revision(repo_id, int(time.time()))
        return result

    def clear_repo(self, repo_id):
        """Remove all rules and advance the revision even when already empty."""
        with transaction.atomic(using=self.db):
            result = self.filter(repo_id=repo_id).delete()
            self._bump_revision(repo_id, int(time.time()))
        return result


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
