"""Compatibility projection of sharing on the single directory ACL record."""
from uuid import uuid4

from ..common.errors import ContractError, invalid
from ..common.validation import object_fields
from .rules import ACLRules, rule_value, digest


def share_value(value):
    """Old shares requests enable sharing; permission edits use the ACL API."""
    object_fields(value, ('path', 'subject'))
    checked = rule_value(dict(path=value['path'], subject=value['subject'],
        kind='dir', permission='r', inherit=True, share_mode=1))
    return dict(path=checked['path'], subject=checked['subject'])


class DirectoryShares:
    """Same-cursor ACL projection; caller owns authorization and repository locks.

    Shared discovery and ACL edits use one ID/revision. Disabling sharing keeps
    the ACL for library members; deleting the ACL removes both access facts.
    """
    FIELDS = ACLRules.FIELDS
    subject_hash = staticmethod(ACLRules._subject_hash)

    def __init__(self, *, lifecycle_reader):
        if not callable(lifecycle_reader):
            raise ValueError('transactional lifecycle reader required')
        self.lifecycle_reader = lifecycle_reader

    @staticmethod
    def _decode(row):
        try:
            result = ACLRules._decode(row)
            if result['share_mode'] != 1:
                raise ValueError('sharing is disabled')
            return result
        except (ValueError, TypeError, ContractError):
            raise ContractError('POLICY_UNAVAILABLE', 'Shared ACL storage is invalid', 503) from None

    def _birth(self, cursor, ref):
        from ..resources.store import ResourceStore
        return ResourceStore._validate_evidence(self.lifecycle_reader(cursor, ref)).lifecycle_ref

    def create(self, cursor, reference, value, *, actor):
        from ..resources.paths import resource_ref
        from ..common.validation import identifier
        ref, value = resource_ref(reference), share_value(value)
        identifier(actor, maximum=225)
        if ref['kind'] != 'dir' or ref['path'] != value['path']:
            raise invalid('Share target must match its directory')
        birth = self._birth(cursor, ref)
        s = value['subject']
        cursor.execute('SELECT ' + self.FIELDS + ' FROM cf_dir_acl '
            "WHERE repo_id=%s AND path_hash=%s AND kind='dir' AND subject_hash=%s FOR UPDATE",
            (ref['repo_id'], digest(ref['path']), self.subject_hash(s)))
        rows = cursor.fetchall()
        if rows:
            if len(rows) != 1:
                raise ContractError('POLICY_UNAVAILABLE', 'Ambiguous shared ACL', 503)
            current = ACLRules._decode(rows[0])
            if current['path'] != ref['path'] or current['subject'] != s:
                raise ContractError('POLICY_UNAVAILABLE', 'Shared ACL identity mismatch', 503)
            if current['share_mode']:
                if current['lifecycle_ref'] != birth:
                    raise ContractError('PATH_STATE_PENDING', 'Disable stale sharing before regranting', 409)
                return current, False
            revision = str(uuid4())
            cursor.execute('UPDATE cf_dir_acl SET share_mode=1,lifecycle_ref=%s,revision=%s '
                'WHERE repo_id=%s AND id=%s', (birth, revision, ref['repo_id'], current['id']))
            return dict(current, share_mode=1, lifecycle_ref=birth, revision=revision, etag='"' + revision + '"'), True
        id_, revision = str(uuid4()), str(uuid4())
        fields = (id_, ref['repo_id'], ref['path'], digest(ref['path']), 'dir', s['type'],
            s['provider'], s['namespace'], s['external_id'], self.subject_hash(s), 'r', 1, revision, 1, birth)
        cursor.execute('INSERT INTO cf_dir_acl (' + self.FIELDS + ') VALUES (' +
            ','.join(['%s'] * len(fields)) + ')', fields)
        return self._decode(fields), True

    def delete(self, cursor, reference, share_id, *, if_match):
        from uuid import UUID
        from ..common.conditions import compare_if_match
        from ..resources.paths import resource_ref
        ref = resource_ref(reference)
        try:
            share_id = str(UUID(share_id))
        except (ValueError, TypeError, AttributeError):
            raise invalid('Invalid share ID') from None
        cursor.execute('SELECT ' + self.FIELDS + ' FROM cf_dir_acl WHERE repo_id=%s AND id=%s AND share_mode=1 FOR UPDATE',
            (ref['repo_id'], share_id))
        rows = cursor.fetchall()
        if not rows:
            raise ContractError('NOT_FOUND', 'Directory sharing does not exist', 404)
        if len(rows) != 1:
            raise ContractError('POLICY_UNAVAILABLE', 'Ambiguous shared ACL', 503)
        current = self._decode(rows[0])
        if ref['kind'] != 'dir' or current['path'] != ref['path']:
            raise ContractError('NOT_FOUND', 'Directory sharing does not exist', 404)
        compare_if_match(if_match, current['etag'])
        # Revocation remains possible after deletion/recreation, and invalidates
        # ACL ETags too so another editor cannot accidentally restore sharing.
        revision = str(uuid4())
        cursor.execute("UPDATE cf_dir_acl SET share_mode=0,lifecycle_ref='',revision=%s WHERE repo_id=%s AND id=%s",
            (revision, ref['repo_id'], share_id))
        if cursor.rowcount != 1:
            raise ContractError('POLICY_UNAVAILABLE', 'Share revocation failed', 503)
        return dict(current, share_mode=0, lifecycle_ref='', revision=revision, etag='"' + revision + '"')

    def candidates(self, cursor, reference, subjects):
        return self.candidates_many(cursor, [reference], subjects)[0]

    def candidates_many(self, cursor, references, subjects):
        from .rules import digest
        from ..resources.paths import resource_ref, is_descendant_or_equal
        from ..common.errors import ContractError
        if not isinstance(references, list) or not 1 <= len(references) <= 50:
            raise invalid('Bounded directory reference batch required')
        refs = [resource_ref(value) for value in references]
        ref = refs[0]
        if any(item['repo_id'] != ref['repo_id'] for item in refs):
            raise invalid('Share batch must belong to one library')
        if not isinstance(subjects, list) or not 1 <= len(subjects) <= 4096:
            raise invalid('Bounded authenticated subjects required')
        normalized = [share_value(dict(path='/scope', subject=s))['subject'] for s in subjects]
        hashes = sorted({self.subject_hash(s) for s in normalized})
        paths = set()
        for target in refs:
            if target['path'] == '/':
                continue
            segments = target['path'].split('/')[1:]
            if len(segments) > 128:
                raise invalid('Directory depth exceeds budget')
            paths.update('/' + '/'.join(segments[:i]) for i in range(1, len(segments) + 1))
        if not paths:
            return [[] for _ in refs]
        if len(paths) > 4096:
            raise invalid('Directory ancestor batch exceeds budget')
        paths = sorted(paths)
        cursor.execute('SELECT ' + self.FIELDS + ' FROM cf_dir_acl WHERE share_mode=1 AND kind=\'dir\' AND repo_id=%s AND path_hash IN (' +
            ','.join(['%s'] * len(paths)) + ') AND subject_hash IN (' + ','.join(['%s'] * len(hashes)) +
            ') ORDER BY id LIMIT 4097 FOR UPDATE', (ref['repo_id'], *(digest(p) for p in paths), *hashes))
        rows = cursor.fetchall()
        if len(rows) > 4096:
            raise ContractError('POLICY_UNAVAILABLE', 'Share candidate budget exceeded', 503)
        result, births = [], {}
        for row in rows:
            item = self._decode(row)
            if item['subject'] not in normalized or not any(is_descendant_or_equal(target['path'], item['path']) for target in refs):
                raise ContractError('POLICY_UNAVAILABLE', 'Share candidate identity mismatch', 503)
            if item['path'] not in births:
                births[item['path']] = self._birth(cursor, dict(repo_id=ref['repo_id'], path=item['path'], kind='dir'))
            if births[item['path']] == item['lifecycle_ref']:
                result.append(item)
        return [[dict(path=item['path'], subject=item['subject']) for item in result
            if item['path'] == target['path'] or (item['inherit'] and
                is_descendant_or_equal(target['path'], item['path']))] for target in refs]
