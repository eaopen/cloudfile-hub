"""Authenticated directory locations and shared-directory discovery."""
import re
from uuid import UUID

from ..common.errors import ContractError, invalid
from ..common.validation import object_fields
from ..resources.paths import resource_ref, is_descendant_or_equal
from .directory_management import subject_keys
from .rules import digest
from .scoped_read import ScopedContentReadAuthority


class DirectoryAccessService:
    def __init__(self, authority):
        if type(authority) is not ScopedContentReadAuthority:
            raise ValueError('scoped content authority required')
        self.authority = authority

    def resolve(self, request):
        object_fields(request, ('reference',), ('shared_root',))
        ref = resource_ref(request['reference'])
        if ref['kind'] != 'dir':
            raise invalid('Directory reference required')
        shared_root = request.get('shared_root')
        if shared_root is not None:
            root_ref = resource_ref(dict(repo_id=ref['repo_id'], path=shared_root, kind='dir'))
            shared_root = root_ref['path']
            if not is_descendant_or_equal(ref['path'], shared_root):
                raise ContractError('ACCESS_DENIED', 'Target is outside shared directory', 403)
        authority = self.authority
        def read(cursor, target):
            # Existing sparse metadata is insufficient to prove native existence.
            authority.shares._birth(cursor, target)
            rules = authority.rules.candidates(target, locking=True)
            shares = authority.shares.candidates(cursor, target, authority.subjects())
            keys = subject_keys(authority.current_subject, authority.state.provider)
            roots = {target['path']}
            if authority.native_permission is not None:
                roots.add('/')
            roots.update(item['path'] for item in shares)
            if shared_root is not None:
                if shared_root not in {item['path'] for item in shares}:
                    raise ContractError('ACCESS_DENIED', 'Shared directory is unavailable', 403)
                roots = {shared_root}
            root = None
            for path in sorted(roots, key=lambda p: (len(p.split('/')), p)):
                decision = authority.core.evaluate_scoped(dict(repo_id=target['repo_id'], path=path, kind='dir'),
                    provider=authority.state.provider, subject=authority.current_subject,
                    rules=rules, ce_permission=authority.native_permission, directory_shares=shares,
                    attribute_allowlist=authority.preparation.contexts.allowlist,
                    hard_readonly=authority.hard_readonly)
                if decision['read'] and authority.scope_allowed(dict(path=path)):
                    root = path
                    break
            if root is None:
                raise ContractError('ACCESS_DENIED', 'Directory root is unavailable', 403)
            return dict(reference=target, root_path=root, initial_path=target['path'],
                permission='rw' if authority.effective_access['write'] else 'r')
        return authority.consume(ref, read)

    def shared_with_me(self, *, limit=50, after=None):
        if type(limit) is not int or not 1 <= limit <= 100:
            raise invalid('Invalid shared-directory page limit')
        cursor_value = None
        if after is not None:
            if not isinstance(after, str) or not re.fullmatch(r'[0-9a-f-]{36}:[0-9a-f]{64}', after):
                raise invalid('Invalid shared-directory cursor')
            repo, hashed = after.split(':')
            try:
                valid_repo = str(UUID(repo)) == repo
            except ValueError:
                valid_repo = False
            if not valid_repo:
                raise invalid('Invalid shared-directory cursor')
            cursor_value = (repo, hashed)
        authority = self.authority
        authority.preparation.prepare(authority.actor)
        with authority.preparation.no_refresh_scope():
            current = authority.preparation.contexts.current(authority.actor)
            if current is None:
                raise ContractError('SUBJECT_UNAVAILABLE', 'Current subject is unavailable', 503)
            subjects = [dict(zip(('type', 'provider', 'namespace', 'external_id'), key))
                for key in subject_keys(current['subject'], authority.state.provider)]
            hashes = sorted({authority.shares.subject_hash(item) for item in subjects})
            if len(hashes) > 4096:
                raise ContractError('POLICY_UNAVAILABLE', 'Subject budget exceeded', 503)
            query = ('SELECT repo_id,path_hash,MIN(path) FROM cf_dir_acl WHERE share_mode=1 AND kind=\'dir\' AND subject_hash IN (' +
                ','.join(['%s'] * len(hashes)) + ')')
            params = list(hashes)
            if cursor_value:
                query += ' AND (repo_id>%s OR (repo_id=%s AND path_hash>%s))'
                params.extend((cursor_value[0], *cursor_value))
            query += ' GROUP BY repo_id,path_hash ORDER BY repo_id,path_hash LIMIT %s'
            params.append(limit + 1)
            with authority.state.connection.cursor() as cursor:
                cursor.execute(query, tuple(params))
                candidates = cursor.fetchall()
            items = []
            for repo, hashed, path in candidates[:limit]:
                if digest(path) != hashed:
                    raise ContractError('POLICY_UNAVAILABLE', 'Invalid shared-directory location', 503)
                try:
                    value = self.resolve(dict(reference=dict(repo_id=repo, path=path, kind='dir'), shared_root=path))
                except ContractError as error:
                    if error.code not in ('ACCESS_DENIED', 'NOT_FOUND', 'RESOURCE_NOT_FOUND'):
                        raise
                    continue
                items.append(value)
            # Advance by scanned locations, not returned items; an all-denied page
            # must still make progress and never reveal denied names/counts.
            next_after = None
            if len(candidates) > limit:
                row = candidates[limit - 1]
                next_after = row[0] + ':' + row[1]
            return dict(items=items, next_after=next_after)
