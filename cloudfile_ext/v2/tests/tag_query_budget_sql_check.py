"""Run only in an explicitly marked disposable database container namespace."""
import os
from pathlib import Path
import sys
import time
from unittest.mock import patch

if os.environ.get('CF_TAG_BUDGET_DISPOSABLE') != '1':
    raise SystemExit('disposable database marker required')
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
import MySQLdb

admin = MySQLdb.connect(host='127.0.0.1', user='root', passwd='')
with admin.cursor() as cursor:
    cursor.execute('CREATE DATABASE IF NOT EXISTS cf_tag_budget_test')
admin.close()

from django.conf import settings
settings.DATABASES = {'default': dict(ENGINE='django.db.backends.mysql', HOST='127.0.0.1',
    NAME='cf_tag_budget_test', USER='root', PASSWORD='', OPTIONS={'charset': 'utf8mb4'})}
import django
django.setup()
from django.db import connection
from cloudfile_ext.v2.tag_reads import _bounded
from cloudfile_ext.v2.tag_http import page_tags


class DelayedRows:
    db = 'default'

    def __init__(self, seconds):
        self.seconds = seconds

    def values_list(self, *fields):
        return self

    def using(self, alias):
        assert alias == self.db
        return self

    def order_by(self, *fields):
        return self

    def __getitem__(self, limit):
        return self

    def __iter__(self):
        with connection.cursor() as cursor:
            cursor.execute('SELECT 1, SLEEP(%s)', [self.seconds])
            return iter(cursor.fetchall())


connection.ensure_connection()
variable = 'max_statement_time' if connection.mysql_is_mariadb else 'max_execution_time'
with connection.cursor() as cursor:
    cursor.execute('SELECT @@SESSION.' + variable)
    before = cursor.fetchone()[0]

def slow_reader(repo, references, *, deadline):
    # The first query consumes part of the same deadline; the second must not
    # receive a fresh full budget or leave an unbounded background query.
    _bounded(DelayedRows(0.080), (), deadline=deadline)
    _bounded(DelayedRows(2), (), deadline=deadline)
    raise AssertionError('slow SELECT was not interrupted')

started = time.monotonic()
with patch('cloudfile_ext.v2.tag_http.read_tags', side_effect=slow_reader):
    result = page_tags('test-repo', [(None, '/open', 'file', 'r')])
elapsed = time.monotonic() - started
assert result == [dict(tag_status='FAILED', tags=None)], result
assert 0.15 <= elapsed < 1, elapsed
with connection.cursor() as cursor:
    cursor.execute('SELECT @@SESSION.' + variable)
    assert cursor.fetchone()[0] == before
    cursor.execute('SELECT 1')
    assert cursor.fetchone() == (1,)

rows = _bounded(DelayedRows(0), (), deadline=time.monotonic() + 0.250)
assert rows == [(1, 0)], rows
assert not connection.execute_wrappers
print(('MariaDB' if connection.mysql_is_mariadb else 'MySQL') +
      ': cancelled slow second tag SELECT in %.3fs; connection/session unchanged' % elapsed)
connection.close()
