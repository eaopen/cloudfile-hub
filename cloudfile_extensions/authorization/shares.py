"""Directory share value contract. A share is READ qualification, not an ACL."""
from ..common.errors import invalid
from ..common.validation import object_fields
from .rules import rule_value


def share_value(value):
    """Validate the two share facts without accepting an ACL permission field."""
    object_fields(value, ('path', 'subject'))
    # Reuse canonical directory and qualified identity validation, never store
    # the temporary validation shape as an ACL row.
    checked = rule_value(dict(path=value['path'], subject=value['subject'],
        kind='dir', permission='r', inherit=True))
    if checked['path'] == '/':
        raise invalid('Directory sharing cannot grant a library root')
    return dict(path=checked['path'], subject=checked['subject'])


class DirectoryShares:
    """Same-cursor persistence; caller owns authority, locks and commit.

    Not a public service. The caller must authorize management before mutations,
    check current identity before queries, and keep the repository guard until
    the consumed effect. Lifecycle evidence comes from the trusted native reader.
    No method writes cf_dir_acl or turns a directory grant into CE qualification.
    """
    FIELDS = ('id,repo_id,path,path_hash,lifecycle_ref,subject_type,provider,namespace,'
              'external_id,subject_hash,revision,created_by')

    def __init__(self, *, lifecycle_reader):
        if not callable(lifecycle_reader):
            raise ValueError('transactional lifecycle reader required')
        self.lifecycle_reader = lifecycle_reader

    @staticmethod
    def subject_hash(subject):
        import hashlib
        import json
        return hashlib.sha256(json.dumps(subject, sort_keys=True,
            ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()

    @staticmethod
    def _decode(row):
        from uuid import UUID
        from .rules import digest
        from ..common.validation import identifier
        from ..common.errors import ContractError
        try:
            id_, repo, path, path_hash, birth, type_, provider, namespace, external, hashed, revision, actor = row
            value = share_value(dict(path=path, subject=dict(type=type_, provider=provider,
                namespace=namespace, external_id=external)))
            if (value['path'] != path or digest(path) != path_hash or
                    DirectoryShares.subject_hash(value['subject']) != hashed or
                    any(str(UUID(v)) != v for v in (id_, repo, revision))):
                raise ValueError('invalid stored share')
            identifier(birth, maximum=512)
            identifier(actor, maximum=225)
            return dict(id=id_, repo_id=repo, **value, lifecycle_ref=birth,
                revision=revision, etag='"' + revision + '"', created_by=actor)
        except (ValueError, TypeError, ContractError):
            raise ContractError('POLICY_UNAVAILABLE', 'Directory share storage is invalid', 503) from None

    def _birth(self, cursor, ref):
        from ..resources.store import ResourceStore
        return ResourceStore._validate_evidence(self.lifecycle_reader(cursor, ref)).lifecycle_ref

    def create(self, cursor, reference, value, *, actor):
        from uuid import uuid4
        from .rules import digest
        from ..resources.paths import resource_ref
        from ..common.validation import identifier
        from ..common.errors import ContractError
        ref, value = resource_ref(reference), share_value(value)
        identifier(actor, maximum=225)
        if ref['kind'] != 'dir' or ref['path'] != value['path']:
            raise invalid('Share target must match its directory')
        birth = self._birth(cursor, ref)
        s = value['subject']
        hashed = self.subject_hash(s)
        cursor.execute('SELECT ' + self.FIELDS + ' FROM cf_dir_share '
            'WHERE repo_id=%s AND path_hash=%s AND subject_hash=%s FOR UPDATE',
            (ref['repo_id'], digest(ref['path']), hashed))
        rows = cursor.fetchall()
        if rows:
            if len(rows) != 1:
                raise ContractError('POLICY_UNAVAILABLE', 'Ambiguous directory share', 503)
            current = self._decode(rows[0])
            if (current['path'] != ref['path'] or current['subject'] != s or current['lifecycle_ref'] != birth):
                raise ContractError('PATH_STATE_PENDING', 'Share lifecycle requires reconciliation', 409)
            return current, False
        id_, revision = str(uuid4()), str(uuid4())
        fields = (id_, ref['repo_id'], ref['path'], digest(ref['path']), birth, s['type'],
            s['provider'], s['namespace'], s['external_id'], hashed, revision, actor)
        cursor.execute('INSERT INTO cf_dir_share (' + self.FIELDS + ',created_at) VALUES (' +
            ','.join(['%s'] * len(fields)) + ',UTC_TIMESTAMP(6))', fields)
        return self._decode(fields), True

    def delete(self, cursor, reference, share_id, *, if_match):
        from uuid import UUID
        from ..common.conditions import compare_if_match
        from ..resources.paths import resource_ref
        from ..common.errors import ContractError
        ref = resource_ref(reference)
        try:
            share_id = str(UUID(share_id))
        except (ValueError, TypeError, AttributeError):
            raise invalid('Invalid share ID') from None
        cursor.execute('SELECT ' + self.FIELDS + ' FROM cf_dir_share WHERE repo_id=%s AND id=%s FOR UPDATE',
            (ref['repo_id'], share_id))
        rows = cursor.fetchall()
        if not rows:
            raise ContractError('NOT_FOUND', 'Directory share does not exist', 404)
        if len(rows) != 1:
            raise ContractError('POLICY_UNAVAILABLE', 'Ambiguous directory share', 503)
        current = self._decode(rows[0])
        if ref['kind'] != 'dir' or current['path'] != ref['path']:
            raise ContractError('NOT_FOUND', 'Directory share does not exist', 404)
        compare_if_match(if_match, current['etag'])
        # Revocation must remain possible after deletion/recreation of the target.
        cursor.execute('DELETE FROM cf_dir_share WHERE repo_id=%s AND id=%s', (ref['repo_id'], share_id))
        if cursor.rowcount != 1:
            raise ContractError('POLICY_UNAVAILABLE', 'Share revocation failed', 503)
        return current

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
        cursor.execute('SELECT ' + self.FIELDS + ' FROM cf_dir_share WHERE repo_id=%s AND path_hash IN (' +
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
                result.append(dict(path=item['path'], subject=item['subject']))
        return [[item for item in result if is_descendant_or_equal(target['path'], item['path'])] for target in refs]
