"""One-time v0.1 group-map upgrade, preserving every native group_id.

Run before the current schema runner on an offline deployment. The old table
is retained as cf_sso_group_map_v01backup; no group is found by display name.
"""
import argparse
import os

from ..common.validation import identifier
from ..jobs.runtime import connect_database
from ..schema.runner import load_migrations
from .project import qualified


OLD = 'cf_sso_group_map'
BACKUP = 'cf_sso_group_map_v01backup'
STAGE = 'cf_sso_group_map_v2stage'
OLD_COLUMNS = {'id', 'provider', 'subject_type', 'external_id', 'group_id',
               'name', 'parent_external_id', 'ctime', 'mtime'}


def _table(cursor, name):
    cursor.execute('SELECT ENGINE FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name=%s', (name,))
    rows = cursor.fetchall()
    if not rows:
        return False
    if rows != (('InnoDB',),):
        raise ValueError('group map table must use InnoDB')
    return True


def migrate(connection, *, native_schema):
    qualified(native_schema, 'Group')
    if not connection.get_autocommit():
        raise ValueError('autocommit connection required')
    with connection.cursor() as cursor:
        cursor.execute("SELECT GET_LOCK('cloudfile.schema.v1',0)")
        if cursor.fetchone() != (1,):
            raise ValueError('schema runner is active')
    try:
        with connection.cursor() as cursor:
            if _table(cursor, BACKUP) or _table(cursor, STAGE):
                raise ValueError('legacy group-map backup or stage already exists')
            if not _table(cursor, OLD):
                raise ValueError('legacy group map does not exist')
            cursor.execute('SELECT column_name FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name=%s', (OLD,))
            columns = {row[0] for row in cursor.fetchall()}
            if columns != OLD_COLUMNS:
                raise ValueError('group map is not the supported v0.1 shape')
            cursor.execute('SELECT id,provider,subject_type,external_id,group_id,name,parent_external_id,ctime,mtime FROM ' + OLD + ' ORDER BY id')
            rows = cursor.fetchall()
            converted, by_external = [], {}
            for row in rows:
                row_id, provider, kind, external, group_id, name, parent, ctime, mtime = row
                if provider != 'cloudfile-sso' or kind not in ('dept', 'group') or type(group_id) is not int or group_id <= 0:
                    raise ValueError('unsupported v0.1 group mapping')
                identifier(external)
                identifier(name)
                if kind == 'dept':
                    if external.startswith('role:'):
                        raise ValueError('department ID collides with role prefix')
                    namespace, current_id = 'directory', external
                else:
                    if not external.startswith('role:'):
                        raise ValueError('v0.1 flat group is not an eTech role')
                    namespace, current_id = 'role', external[5:]
                    identifier(current_id)
                    if parent is not None:
                        raise ValueError('role cannot have a parent')
                if external in by_external:
                    raise ValueError('duplicate v0.1 external ID')
                by_external[external] = group_id
                converted.append((row_id, 'etech', kind, namespace, current_id, group_id,
                                  name, parent, ctime, mtime))
            native = qualified(native_schema, 'Group')
            structure = qualified(native_schema, 'GroupStructure')
            departments = {row[4]: row for row in converted if row[2] == 'dept'}
            def department_path(external_id, walked):
                if external_id in walked:
                    raise ValueError('v0.1 department parent cycle')
                row = departments[external_id]
                parent = row[7]
                if parent is None:
                    return str(row[5])
                if parent not in departments:
                    raise ValueError('v0.1 department parent is not a department')
                return department_path(parent, walked | {external_id}) + ', ' + str(row[5])
            for old, new in zip(rows, converted):
                kind, parent, group_id = new[2], new[7], new[5]
                if parent is not None and parent not in by_external:
                    raise ValueError('v0.1 department parent is unmapped')
                expected_parent = by_external[parent] if parent else -1 if kind == 'dept' else 0
                cursor.execute('SELECT parent_group_id FROM ' + native + ' WHERE group_id=%s', (group_id,))
                if cursor.fetchall() != ((expected_parent,),):
                    raise ValueError('native group hierarchy differs from v0.1 mapping')
                if kind == 'dept':
                    cursor.execute('SELECT path FROM ' + structure + ' WHERE group_id=%s', (group_id,))
                    if cursor.fetchall() != ((department_path(old[3], set()),),):
                        raise ValueError('native department path differs from v0.1 mapping')
            migration = next(item for item in load_migrations() if item.version == '006_group_maps')
            prefix = 'CREATE TABLE cf_sso_group_map '
            if not migration.steps[0]['sql'].startswith(prefix):
                raise ValueError('current group-map schema is unsupported')
            create = 'CREATE TABLE ' + STAGE + ' ' + migration.steps[0]['sql'][len(prefix):]
            cursor.execute(create)
            for row in converted:
                cursor.execute('INSERT INTO ' + STAGE + '(id,provider,subject_type,namespace,external_id,group_id,name,parent_external_id,ctime,mtime) '
                               'VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)', row)
            cursor.execute('SELECT COUNT(*) FROM ' + STAGE)
            if cursor.fetchone() != (len(rows),):
                raise ValueError('group-map copy count differs')
            cursor.execute('RENAME TABLE ' + OLD + ' TO ' + BACKUP + ', ' + STAGE + ' TO ' + OLD)
            return len(rows)
    finally:
        with connection.cursor() as cursor:
            cursor.execute("SELECT RELEASE_LOCK('cloudfile.schema.v1')")


def main(argv=None):
    parser = argparse.ArgumentParser(description='Upgrade the v0.1 eTech group map before schema apply')
    parser.add_argument('--native-schema', required=True)
    arguments = parser.parse_args(argv)
    connection = connect_database(os.environ)
    try:
        count = migrate(connection, native_schema=arguments.native_schema)
        print('Migrated %d v0.1 group mappings; old table retained as %s' % (count, BACKUP))
    finally:
        connection.close()


if __name__ == '__main__':
    main()
