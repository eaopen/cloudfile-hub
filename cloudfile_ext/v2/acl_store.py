"""Sparse V2 ACL storage. Writers serialize with native Branch(master) CAS.

No legacy tables or user-supplied SQL identifiers. SQL errors never mean no ACL.
"""
from contextlib import contextmanager
from dataclasses import asdict
from hashlib import sha256
from uuid import UUID

from .acl_policy import Rule, PolicyError, StoredACLError, ancestors, canonical_path
from .schema import identifier


class RevisionConflict(Exception):
    pass


def uuid(value):
    if not isinstance(value, str) or str(UUID(value)) != value:
        raise PolicyError('canonical UUID required')
    return value


def subject_filter(principal):
    subjects = [('user', 'user', principal.uid), *sorted(principal.groups)]
    if len(subjects) > 4096:
        raise PolicyError('subject budget exceeded')
    sql = ' OR '.join('(subject_type=%s AND namespace=%s AND external_id=%s)' for _ in subjects)
    return '(provider=%s AND (' + sql + '))', [principal.provider, *(v for s in subjects for v in s)]


COLUMNS = 'repo_id,path,provider,subject_type,namespace,external_id,permission,inherit,share_mode,revision,path_hash'


def path_digest(path):
    return sha256(path.encode()).digest()


def validate(rule):
    Rule(**asdict(rule))
    uuid(rule.repo_id)
    if (len(rule.provider) > 32 or len(rule.namespace) > 128 or len(rule.external_id) > 225
            or (rule.subject_type == 'user' and rule.namespace != 'user')):
        raise PolicyError('invalid stored subject')


def decode(row):
    if len(row) != 11 or row[7] not in (0, 1) or row[8] not in (0, 1):
        raise StoredACLError('malformed stored ACL')
    try:
        rule = Rule(*row[:7], bool(row[7]), bool(row[8]))
        validate(rule)
        uuid(row[9])
    except ValueError as error:  # PolicyError and a malformed UUID are both stored-data faults
        raise StoredACLError('malformed stored ACL: %s' % error) from None
    if not isinstance(row[10], (bytes, bytearray, memoryview)):
        # The contract column is BINARY(32); a text cell means the table is not
        # this one. Name it instead of letting bytes(str) raise a TypeError that
        # a caller mistakes for a bad request.
        raise StoredACLError('stored path_hash is not binary')
    if bytes(row[10]) != path_digest(rule.path):
        raise StoredACLError('ACL path hash mismatch')
    return rule, row[9]


class ACLStore:
    def __init__(self, connection, schema, atomic, changed=None):
        # changed(repo_id) runs after a committed write, e.g. cache invalidation.
        self.connection, self.atomic, self.changed = connection, atomic, changed
        self.schema = schema
        self.table = identifier(schema) + '.cf_dir_acl'
        self.branch = identifier(schema) + '.Branch'

    def _read(self, where, args):
        with self.connection.cursor() as cursor:
            cursor.execute('SELECT ' + COLUMNS + ' FROM ' + self.table + ' WHERE ' + where + ' LIMIT 4097', args)
            rows = cursor.fetchall()
        if len(rows) > 4096:
            raise PolicyError('ACL candidate budget exceeded')
        return [decode(row) for row in rows]

    def candidates(self, repo_id, path, principal):
        hashes = [path_digest(p) for p in ancestors(path)]
        selector, args = subject_filter(principal)
        return self._read('repo_id=%s AND path_hash IN (' + ','.join(['%s'] * len(hashes)) + ') AND ' + selector,
                          [uuid(repo_id), *hashes, *args])

    def library(self, repo_id):
        """All sparse rules of one library for the shared cache; None over budget."""
        with self.connection.cursor() as cursor:
            cursor.execute('SELECT ' + COLUMNS + ' FROM ' + self.table + ' WHERE repo_id=%s LIMIT 4097', [uuid(repo_id)])
            rows = cursor.fetchall()
        if len(rows) > 4096:
            return None
        return tuple(decode(row)[0] for row in rows)

    def shared(self, principal):
        selector, args = subject_filter(principal)
        return self._read(selector + ' AND share_mode=1', args)

    def list_path(self, repo_id, path, provider):
        canonical_path(path)
        result = self._read('repo_id=%s AND path_hash=%s AND provider=%s',
                            [uuid(repo_id), path_digest(path), provider])
        if any(rule.path != path for rule, _ in result):
            raise StoredACLError('ACL hash collision')
        return result

    @contextmanager
    def transfer_fence(self, repo_id):
        # Native synchronous transfers hold the same lock through publication.
        # Take it before Branch(master) to avoid lock-order inversion with CAS.
        key = 'cfv2:t:' + sha256((self.schema + ':' + repo_id).encode()).hexdigest()[:56]
        with self.connection.cursor() as cursor:
            cursor.execute('SELECT GET_LOCK(%s,5)', [key])
            if cursor.fetchone() != (1,):
                raise PolicyError('native transfer in progress')
        try:
            yield
        finally:
            with self.connection.cursor() as cursor:
                cursor.execute('SELECT RELEASE_LOCK(%s)', [key])
                if cursor.fetchone() != (1,):
                    raise PolicyError('native transfer fence lost')

    def mutate(self, rule, *, expected, revision, delete=False):
        """Internal writer only; public publication remains blocked until release review.

        expected=None creates; otherwise compare-and-swap the exact row revision.
        revision is a caller UUID retry key: same revision + identical row is replay.
        """
        validate(rule)
        uuid(revision)
        if expected is not None:
            uuid(expected)
        key = (rule.repo_id, path_digest(rule.path), rule.subject_type,
               rule.provider, rule.namespace, rule.external_id)
        where = 'repo_id=%s AND path_hash=%s AND subject_type=%s AND provider=%s AND namespace=%s AND external_id=%s'
        with self.transfer_fence(rule.repo_id), self.atomic():
            with self.connection.cursor() as cursor:
                cursor.execute('SELECT commit_id FROM ' + self.branch + " WHERE repo_id=%s AND name='master' FOR UPDATE", [rule.repo_id])
                if len(cursor.fetchall()) != 1:
                    raise PolicyError('native master branch missing')
                cursor.execute('SELECT ' + COLUMNS + ' FROM ' + self.table + ' WHERE ' + where + ' FOR UPDATE', key)
                rows = cursor.fetchall()
                current = decode(rows[0]) if len(rows) == 1 else None
                if len(rows) > 1 or (current and current[0].path != rule.path):
                    raise StoredACLError('conflicting stored ACL')
                if not delete and current == (rule, revision):
                    return revision
                if (current[1] if current else None) != expected or (current and current[1] == revision):
                    raise RevisionConflict()
                if delete:
                    if expected is None:
                        raise RevisionConflict()
                    cursor.execute('DELETE FROM ' + self.table + ' WHERE ' + where, key)
                elif current:
                    cursor.execute('UPDATE ' + self.table + ' SET permission=%s,inherit=%s,share_mode=%s,revision=%s WHERE ' + where,
                                   [rule.permission, int(rule.inherit), int(rule.share_mode), revision, *key])
                else:
                    cursor.execute('INSERT INTO ' + self.table + ' (' + COLUMNS + ') VALUES (' + ','.join(['%s'] * 11) + ')',
                                   [rule.repo_id, rule.path, rule.provider, rule.subject_type, rule.namespace,
                                    rule.external_id, rule.permission, int(rule.inherit), int(rule.share_mode), revision,
                                    key[1]])
        if self.changed is not None:
            self.changed(rule.repo_id)
        return revision
