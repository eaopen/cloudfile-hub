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

from tests.isolated_native import install
install()
from django.conf import settings
settings.DATABASES = {'default': dict(ENGINE='django.db.backends.mysql', HOST='127.0.0.1',
    NAME='cf_tag_budget_test', USER='root', PASSWORD='', OPTIONS={'charset': 'utf8mb4'})}
from django.db import connection
from cloudfile_ext.v2.tag_reads import _bounded
from cloudfile_ext.v2.tag_http import page_tags


class DelayedRows:
    db = 'default'

    def __init__(self, seconds, *, scan=False):
        self.seconds = seconds
        self.scan = scan

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
            if self.scan:
                # Unlike SLEEP(), this exercises normal SELECT cancellation.
                # MySQL can interrupt SLEEP by returning a value, not an error.
                cursor.execute('SELECT SUM(a.n + b.n + c.n + d.n) '
                    'FROM cf_tag_budget_probe a CROSS JOIN cf_tag_budget_probe b '
                    'CROSS JOIN cf_tag_budget_probe c CROSS JOIN cf_tag_budget_probe d')
            else:
                cursor.execute('SELECT 1, SLEEP(%s)', [self.seconds])
            return iter(cursor.fetchall())


connection.ensure_connection()
variable = 'max_statement_time' if connection.mysql_is_mariadb else 'max_execution_time'
with connection.cursor() as cursor:
    cursor.execute('CREATE TABLE IF NOT EXISTS cf_tag_budget_probe (n INTEGER NOT NULL)')
    cursor.execute('TRUNCATE TABLE cf_tag_budget_probe')
    cursor.executemany('INSERT INTO cf_tag_budget_probe (n) VALUES (%s)', [(n,) for n in range(100)])
    cursor.execute('SELECT @@SESSION.' + variable)
    before = cursor.fetchone()[0]

interruptions = []


def slow_reader(repo, references, *, deadline):
    # The first query consumes part of the same deadline; the second must not
    # receive a fresh full budget or leave an unbounded background query.
    _bounded(DelayedRows(0.080), (), deadline=deadline)
    try:
        _bounded(DelayedRows(2, scan=True), (), deadline=deadline)
    except Exception as error:
        interruptions.append(error)
        raise
    raise AssertionError('slow SELECT was not interrupted')

started = time.monotonic()
with patch('cloudfile_ext.v2.tag_http.read_tags', side_effect=slow_reader):
    result = page_tags('test-repo', [(None, '/open', 'file', 'r')])
elapsed = time.monotonic() - started
assert result == [dict(tag_status='FAILED', tags=None)], result
assert len(interruptions) == 1, interruptions
# A Python deadline check or unrelated SQL error must not masquerade as
# successful server cancellation (MariaDB 1969 / MySQL 3024).
expected_code = 1969 if connection.mysql_is_mariadb else 3024
assert interruptions[0].args[0] == expected_code, repr(interruptions[0])
assert 0.15 <= elapsed < 1, elapsed
with connection.cursor() as cursor:
    cursor.execute('SELECT @@SESSION.' + variable)
    assert cursor.fetchone()[0] == before
    cursor.execute('SELECT 1')
    assert cursor.fetchone() == (1,)

rows = _bounded(DelayedRows(0), (), deadline=time.monotonic() + 0.250)
assert rows == [(1, 0)], rows
assert not connection.execute_wrappers


def fast_reader(repo, references, *, deadline):
    _bounded(DelayedRows(0.005), (), deadline=deadline)
    _bounded(DelayedRows(0.005), (), deadline=deadline)
    return {('/open', 'file'): [dict(tag_name='normal')]}


with patch('cloudfile_ext.v2.tag_http.read_tags', side_effect=fast_reader):
    assert page_tags('test-repo', [(None, '/open', 'file', 'r')]) == [
        dict(tag_status='OK', tags=[dict(tag_name='normal')])]
assert not connection.execute_wrappers
print(('MariaDB' if connection.mysql_is_mariadb else 'MySQL') +
      ': cancelled slow second tag SELECT in %.3fs; connection/session unchanged' % elapsed)
connection.close()
