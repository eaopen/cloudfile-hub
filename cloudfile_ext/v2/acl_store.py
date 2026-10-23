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

    def provider_snapshot(self, repo_id, provider, *, lock=False):
        """Complete bounded provider view, for versioned publisher GET/PUT only.

        Native browse reads still use the shared library_rules cache. For writes,
        the current-read uses the existing repo_id PRIMARY prefix under Branch;
        the provider predicate cannot broaden the lock into unrelated libraries.
        """
        uuid(repo_id)
        if not isinstance(provider, str) or not provider or len(provider) > 32:
            raise PolicyError('invalid ACL provider')
        sql = ('SELECT ' + COLUMNS + ' FROM ' + self.table +
               ' FORCE INDEX (PRIMARY) WHERE repo_id=%s AND provider=%s LIMIT 4097')
        if lock:
            sql += ' FOR UPDATE'
        with self.connection.cursor() as cursor:
            cursor.execute(sql, [repo_id, provider])
            rows = cursor.fetchall()
        if len(rows) > 4096:
            raise PolicyError('provider ACL snapshot exceeds safe batch limit')
        return tuple(decode(row) for row in rows)

    def replace_owned(self, repo_id, provider, *, expected, managed, desired):
        """One-library, one-transaction differential publication.

        `managed` is the Etech publisher's explicit old+new set of natural keys,
        never a licence to delete every provider row. A mismatching complete
        provider snapshot fails 409 rather than applying a stale diff. Per-rule
        API semantics and third-party provider rows are unchanged.
        """
        import re
        from uuid import uuid4
        from .acl_batch import fingerprint, key_of
        uuid(repo_id)
        if not isinstance(expected, str) or not re.fullmatch(r'[0-9a-f]{64}', expected):
            raise PolicyError('invalid expected ACL fingerprint')
        if not isinstance(managed, (list, tuple, set)) or len(managed) > 4096:
            raise PolicyError('invalid ACL managed keys')
        if not isinstance(desired, (list, tuple)) or len(desired) > 4096:
            raise PolicyError('invalid desired ACL rules')
        managed_keys = set()
        for item in managed:
            if not isinstance(item, tuple) or len(item) != 4:
                raise PolicyError('invalid managed key')
            rule = Rule(repo_id, item[0], provider, item[1], item[2],
                        item[3], 'r', True, False)
            validate(rule)
            if item in managed_keys:
                raise PolicyError('duplicate managed key')
            managed_keys.add(item)
        desired_map = {}
        for rule in desired:
            if not isinstance(rule, Rule) or rule.repo_id != repo_id or rule.provider != provider:
                raise PolicyError('foreign desired ACL rule')
            validate(rule)
            key = key_of(rule)
            if key not in managed_keys or key in desired_map:
                raise PolicyError('unmanaged or duplicate desired ACL rule')
            desired_map[key] = rule

        changed = inserted = updated = deleted = unchanged = 0
        with self.transfer_fence(repo_id), self.atomic():
            with self.connection.cursor() as cursor:
                cursor.execute('SELECT commit_id FROM ' + self.branch +
                               " WHERE repo_id=%s AND name='master' FOR UPDATE", [repo_id])
                if len(cursor.fetchall()) != 1:
                    raise PolicyError('native master branch missing')
            current = self.provider_snapshot(repo_id, provider, lock=True)
            if fingerprint(current) != expected:
                raise RevisionConflict()
            state = {key_of(rule): (rule, revision) for rule, revision in current}
            if len(state) != len(current):
                raise StoredACLError('duplicate provider ACL natural key')
            additions = len([key for key in desired_map if key not in state])
            removals = len([key for key in managed_keys if key in state and key not in desired_map])
            if len(state) + additions - removals > 4096:
                raise PolicyError('resulting provider ACL exceeds safe batch limit')
            where = ('repo_id=%s AND path_hash=%s AND subject_type=%s AND '
                     'provider=%s AND namespace=%s AND external_id=%s')
            with self.connection.cursor() as cursor:
                for key in sorted(managed_keys):
                    before = state.get(key)
                    after = desired_map.get(key)
                    # Keys are canonical (path,type,namespace,external_id).
                    args = [repo_id, path_digest(key[0]), key[1], provider, key[2], key[3]]
                    if after is None:
                        if before is not None:
                            cursor.execute('DELETE FROM ' + self.table + ' WHERE ' + where, args)
                            if cursor.rowcount != 1:
                                raise StoredACLError('ACL delete lost natural key')
                            state.pop(key)
                            deleted += 1
                    elif before is not None and before[0] == after:
                        unchanged += 1
                    elif before is not None:
                        revision = str(uuid4())
                        cursor.execute('UPDATE ' + self.table +
                                       ' SET permission=%s,inherit=%s,share_mode=%s,revision=%s WHERE ' + where,
                                       [after.permission, int(after.inherit), int(after.share_mode), revision, *args])
                        if cursor.rowcount != 1:
                            raise StoredACLError('ACL update lost natural key')
                        state[key] = (after, revision)
                        updated += 1
                    else:
                        revision = str(uuid4())
                        cursor.execute('INSERT INTO ' + self.table + ' (' + COLUMNS + ') VALUES (' +
                                       ','.join(['%s'] * 11) + ')',
                                       [repo_id, after.path, provider, after.subject_type, after.namespace,
                                        after.external_id, after.permission, int(after.inherit),
                                        int(after.share_mode), revision, path_digest(after.path)])
                        state[key] = (after, revision)
                        inserted += 1
        changed = inserted + updated + deleted
        if changed and self.changed is not None:
            self.changed(repo_id)  # generation invalidation once, after COMMIT
        return dict(fingerprint=fingerprint(state.values()), inserted=inserted,
                    updated=updated, deleted=deleted, unchanged=unchanged)

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
