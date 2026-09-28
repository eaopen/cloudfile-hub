# -*- coding: utf-8 -*-
"""Library shares CloudFile itself applied, on behalf of an external system.

Decision source: eap-cloudfile docs/review/cloudfile_decision_20260827.md §4.3.

The boundary this table draws is the whole point of the design. Seafile lets
anybody with the right to share hand a library to a group, and the share it
creates is indistinguishable from any other: same table, same shape, no owner
column. An external system that reconciles "what should be shared" against
"what is shared" therefore cannot tell its own work apart from a person's --
and a reconcile loop that cannot tell its own work apart from a person's will
eventually delete a person's access, which is the failure this file exists to
make structurally impossible.

So the applied state is recorded here, keyed by the external system's own
stable ids::

    provider + external_group_id + repo_id
        -> seafile_group_id + applied_permission + state + last_error

and only rows that are here may be revoked. A share that shows up in Seafile
without a row here was made by hand (or by something else), and the reconcile
loop leaves it alone.

Why cf_sso_group_map is not enough
----------------------------------

The group map says "this external id is that Seafile group". It does not say
who shared what to whom, nor with which permission, nor whether the applying
system still stands behind it. Sharing state needs its own ledger, because
revocation decisions are made per (library, group), not per group.

Why the table is in seafile-db
------------------------------

Same reason as every cf_* table (see cloudfile_ext.sso.models): one schema
mechanism, applied on every start, covering fresh installs, upgrades and an
existing CE deployment adopting CloudFile alike.
"""

import time

from django.db import models

#: Fixed provider key, for the same reason cloudfile_ext.sso.service.PROVIDER
#: is fixed: switching the external system must not orphan the ledger.
PROVIDER = 'cloudfile-sso'

STATE_ACTIVE = 'ACTIVE'
STATE_REVOKED = 'REVOKED'
STATE_ERROR = 'ERROR'

PERMISSIONS = ('r', 'rw')


class ManagedLibraryShareManager(models.Manager):

    def as_dict(self, repo_id):
        """``{external_group_id: row-dict}`` for one repo, active or not.

        Revoke decisions need the revoked rows too -- an entry that was
        applied and then revoked must not be re-applied by a later reconcile
        that misreads the ledger.
        """
        rows = self.filter(provider=PROVIDER, repo_id=repo_id).values(
            'external_group_id', 'seafile_group_id', 'permission', 'state',
            'last_error')
        return {row['external_group_id']: row for row in rows}

    def record_applied(self, repo_id, external_group_id, seafile_group_id,
                       permission):
        now = int(time.time())
        # Django 4.2+ contract: when create_defaults is given, the CREATE branch
        # uses only lookup kwargs + create_defaults -- `defaults` is ignored
        # entirely. A previous version repeated the field dict in both places
        # by hand and the create copy was missing seafile_group_id, so the
        # very first ledger insert (empty table) wrote NULL into a NOT NULL
        # column: MySQL 1048 "Column 'seafile_group_id' cannot be null".
        # Build one field dict and derive create_defaults from it.
        fields = {
            'seafile_group_id': seafile_group_id,
            'permission': permission,
            'state': STATE_ACTIVE,
            'last_error': '',
            'mtime': now,
        }
        obj, _created = self.update_or_create(
            provider=PROVIDER,
            repo_id=repo_id,
            external_group_id=external_group_id,
            defaults=fields,
            create_defaults={**fields, 'ctime': now},
        )
        return obj

    def record_revoked(self, repo_id, external_group_id):
        return self.filter(
            provider=PROVIDER, repo_id=repo_id,
            external_group_id=external_group_id,
        ).update(state=STATE_REVOKED, mtime=int(time.time()))

    def record_error(self, repo_id, external_group_id, error):
        return self.filter(
            provider=PROVIDER, repo_id=repo_id,
            external_group_id=external_group_id,
        ).update(state=STATE_ERROR, last_error=str(error)[:1000],
                 mtime=int(time.time()))


class ManagedLibraryShare(models.Model):
    provider = models.CharField(max_length=32)
    repo_id = models.CharField(max_length=36)
    #: The external system's stable group id. Never the Seafile numeric id:
    #: the ledger has to survive a Seafile rebuild, and numeric ids do not.
    external_group_id = models.CharField(max_length=128)
    #: Resolved at apply time from cf_sso_group_map. Diagnostic only -- the
    #: authoritative mapping is re-read from the group map on every reconcile,
    #: so a group recreated under a new id heals on the next run.
    seafile_group_id = models.IntegerField()
    permission = models.CharField(max_length=8)
    state = models.CharField(max_length=16)
    last_error = models.CharField(max_length=1000, null=True)
    ctime = models.BigIntegerField(null=True)
    mtime = models.BigIntegerField(null=True)

    objects = ManagedLibraryShareManager()

    class Meta:
        managed = False
        db_table = 'cf_managed_library_share'
        app_label = 'cloudfile_ext'
        unique_together = ('provider', 'repo_id', 'external_group_id')

    def __str__(self):
        return '%s:%s/%s -> group %s (%s)' % (
            self.provider, self.repo_id, self.external_group_id,
            self.seafile_group_id, self.state)
