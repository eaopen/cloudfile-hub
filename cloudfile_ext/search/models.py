# -*- coding: utf-8 -*-
"""How far the meilisearch indexer has walked seafevents' Activity table.

One row per provider that needs its own index built by cf-worker -- currently
just 'meilisearch'. SeaSearch needs no row here: seafevents indexes it
directly, and CloudFile never touches that pipeline (docs/search.md).

Same reasoning as cloudfile_ext.sso.models.SSOSyncState for why this lives in
seafile-db via cf_search_index_state rather than as a Django-migrated table:
one schema mechanism (cloudfile-server's cloudfile.sql, applied on every
start) instead of a second one to carry across upstream merges.
"""

import time

from django.db import models


class SearchIndexStateManager(models.Manager):

    def get_cursor(self, name):
        """Last Activity.id this provider's indexer has consumed, or 0."""
        row = self.filter(name=name).first()
        return row.last_activity_id if row else 0

    def advance(self, name, last_activity_id, status, detail=''):
        now = int(time.time())
        obj, _created = self.update_or_create(
            name=name,
            defaults={
                'last_activity_id': last_activity_id,
                'last_run': now,
                'status': status,
                'detail': detail[:2000],
            },
        )
        return obj


class SearchIndexState(models.Model):
    name = models.CharField(max_length=64, unique=True)
    last_activity_id = models.BigIntegerField(default=0)
    last_run = models.BigIntegerField(null=True)
    status = models.CharField(max_length=16)
    detail = models.TextField(null=True)

    objects = SearchIndexStateManager()

    class Meta:
        managed = False
        db_table = 'cf_search_index_state'
        app_label = 'cloudfile_ext'

    def __str__(self):
        return '%s: cursor=%s %s @%s' % (
            self.name, self.last_activity_id, self.status, self.last_run)
