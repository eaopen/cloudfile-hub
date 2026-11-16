"""Read the current per-repository capability from Seafile's database."""

from django.db import connection
from seahub.utils.db_api import SeafileDB

from .schema import identifier


def enabled(repo_id, feature, *, locked=False):
    # Never cache this result. Operators can change one library while workers
    # are running and a failed database read must not silently disable a fence.
    table = identifier(SeafileDB().db_name) + '.cf_repo_feature'
    with connection.cursor() as cursor:
        query = 'SELECT 1 FROM ' + table + ' WHERE repo_id=%s AND feature=%s'
        cursor.execute(query + (' LOCK IN SHARE MODE' if locked else ''),
                       (repo_id, feature))
        return cursor.fetchone() is not None
