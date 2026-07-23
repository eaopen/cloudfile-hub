# -*- coding: utf-8 -*-
"""Which Seafile groups CloudFile created, and when it last synced.

``cf_sso_group_map`` is the whole safety boundary of the directory sync: a
group is in this table exactly when CloudFile created it, and the reconciler
will not touch anything else (cloudfile_ext.sso.reconcile). Losing a row does
not corrupt anything -- it just makes CloudFile stop managing that group and
create a fresh one on the next tick -- but *adding* a row by hand hands the
sync a group somebody else owns, so the table is written only by the sync and
by the admin API that removes entries.

Why not upstream's ``external_department``
------------------------------------------

Seahub already has that table, and WeCom/DingTalk department import uses it.
It cannot be reused here: ``outer_id`` is a BIGINT, and a generic directory
identifies a group with a string -- an LDAP DN, an OIDC group claim, a UUID.
It also has nowhere to record the group's name, which is what tells a rename
apart from a new group. Reusing it would mean widening an upstream column,
which is exactly the kind of change this fork spends its budget avoiding.

Why the table is in seafile-db
------------------------------

Not because anything below the Hub reads it -- nothing does; group membership
is enforced through ccnet, which every layer already consults. It is there
because that is where the one schema mechanism puts cf_* tables
(cloudfile.sql, applied on every start, covering fresh installs, upgrades and
an existing CE deployment adopting CloudFile alike). Putting this one table in
seahub-db instead would mean a second schema path and a Django migration
history to carry across upstream merges, to save nothing.
"""

import time

from django.db import models


class SSOGroupMapManager(models.Manager):

    def as_dict(self, provider):
        """``{external_id: {'group_id', 'name'}}`` -- the reconciler's input."""
        rows = self.filter(provider=provider).values(
            'external_id', 'group_id', 'name')
        return {row['external_id']: {'group_id': row['group_id'],
                                     'name': row['name']}
                for row in rows}

    def add(self, provider, external_id, group_id, name):
        now = int(time.time())
        return self.create(provider=provider, external_id=external_id,
                           group_id=group_id, name=name, ctime=now, mtime=now)

    def rename(self, provider, external_id, name):
        return self.filter(provider=provider, external_id=external_id).update(
            name=name, mtime=int(time.time()))

    def unmap(self, provider, external_id):
        """Stop managing a group without deleting it.

        The group may own libraries and be shared into, so removing it is a
        decision for a person; a sync tick must not be able to take it.
        """
        return self.filter(provider=provider, external_id=external_id).delete()


class SSOGroupMap(models.Model):
    provider = models.CharField(max_length=32, db_index=True)
    #: The directory's own identifier. A string, not a number: OIDC group
    #: claims and LDAP DNs are both text.
    external_id = models.CharField(max_length=255)
    group_id = models.IntegerField(unique=True)
    #: Last name we synced. Kept so a rename is distinguishable from a new
    #: group -- without it every rename in the directory would orphan the old
    #: group and create a second one.
    name = models.CharField(max_length=255)
    ctime = models.BigIntegerField(null=True)
    mtime = models.BigIntegerField(null=True)

    objects = SSOGroupMapManager()

    class Meta:
        managed = False
        db_table = 'cf_sso_group_map'
        app_label = 'cloudfile_ext'
        unique_together = ('provider', 'external_id')

    def __str__(self):
        return '%s:%s -> group %s' % (self.provider, self.external_id,
                                      self.group_id)


class SSOSyncStateManager(models.Manager):

    def record(self, name, status, detail=''):
        now = int(time.time())
        obj, _created = self.update_or_create(
            name=name,
            defaults={'last_run': now, 'status': status, 'detail': detail[:2000]},
        )
        return obj

    def get_state(self, name):
        return self.filter(name=name).first()


class SSOSyncState(models.Model):
    """When the last sync ran and how it went.

    This is not bookkeeping for its own sake. Directory mapping is eventually
    consistent by design -- the trade taken in docs/sso-mapping.md -- and that
    trade is only acceptable if "how stale is this?" has an answer an operator
    can read. A refusal (cloudfile_ext.sso.reconcile.SyncRefused) lands here
    too, so a feed that has been failing for a week is visible rather than
    silent.
    """

    name = models.CharField(max_length=64, unique=True)
    last_run = models.BigIntegerField(null=True)
    status = models.CharField(max_length=16)
    detail = models.TextField(null=True)

    objects = SSOSyncStateManager()

    class Meta:
        managed = False
        db_table = 'cf_sso_sync_state'
        app_label = 'cloudfile_ext'

    def __str__(self):
        return '%s: %s @%s' % (self.name, self.status, self.last_run)
