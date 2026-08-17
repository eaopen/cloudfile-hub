# Copyright (c) 2012-2016 Seafile Ltd.
# -*- coding: utf-8 -*-
"""Backfill obj_id on favorite rows written before the object-id migration.

Runs idempotently and losslessly: for every ``UserStarredFiles`` row that has
no ``obj_id``, it resolves the object id from the stored ``repo_id + path`` and
stores it. Rows whose repo or path no longer resolve are left untouched -- they
are never deleted -- so the migration can be re-run after data is restored.
"""
import logging

from django.core.management.base import BaseCommand

from seahub.base.models import UserStarredFiles
from seahub.utils.star import backfill_row_obj_id

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Backfill obj_id on starred items that predate object-id favorites.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--limit', type=int, default=0,
            help='Only process this many rows (0 = all rows).')

    def handle(self, *args, **options):
        limit = options['limit']
        rows = UserStarredFiles.objects.filter(obj_id__isnull=True)
        if limit > 0:
            rows = rows[:limit]

        total = 0
        filled = 0
        for row in rows.iterator():
            total += 1
            if backfill_row_obj_id(row):
                filled += 1

        self.stdout.write(
            'Starred obj_id backfill: %d rows scanned, %d filled, %d left '
            'unresolved.' % (total, filled, total - filled))
