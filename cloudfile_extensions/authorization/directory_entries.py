"""Bounded native directory pages under the current scoped read transaction."""
from contextlib import contextmanager
import re

from ..common.errors import ContractError, invalid
from ..common.validation import object_fields
from ..resources.paths import resource_ref
from ..search.native_directory import NativeCommitDirectoryReader
from .scoped_read import ScopedContentReadAuthority


class DirectoryEntriesService:
    def __init__(self, authority):
        if type(authority) is not ScopedContentReadAuthority:
            raise ValueError('scoped content authority required')
        self.authority = authority

    def list(self, request, *, limit=50, after=None):
        object_fields(request, ('reference',), ('shared_root',))
        ref = resource_ref(request['reference'])
        if ref['kind'] != 'dir' or type(limit) is not int or not 1 <= limit <= 100:
            raise invalid('Directory and bounded page required')
        expected_head, offset = None, 0
        if after is not None:
            if not isinstance(after, str) or not re.fullmatch(r'[0-9a-f]{40}:[0-9]{1,10}', after):
                raise invalid('Invalid directory cursor')
            expected_head, position = after.split(':')
            offset = int(position)
            if offset > 2 ** 31 - 102:
                raise invalid('Invalid directory offset')
        authority = self.authority
        shared_root = request.get('shared_root')
        if shared_root is not None:
            from ..resources.paths import normalize_path, is_descendant_or_equal
            shared_root = normalize_path(shared_root, 'dir')
            if not is_descendant_or_equal(ref['path'], shared_root):
                raise ContractError('ACCESS_DENIED', 'Target is outside shared directory', 403)

        def read(cursor, target):
            authority.shares._birth(cursor, target)
            shares = authority.shares.candidates(cursor, target, authority.subjects())
            if shared_root is not None and shared_root not in {item['path'] for item in shares}:
                raise ContractError('ACCESS_DENIED', 'Shared directory is unavailable', 403)
            cursor.execute("SELECT commit_id FROM Branch WHERE repo_id=%s AND name='master' FOR UPDATE", (target['repo_id'],))
            rows = cursor.fetchall()
            if len(rows) != 1 or not isinstance(rows[0][0], str) or not re.fullmatch(r'[0-9a-f]{40}', rows[0][0]):
                raise ContractError('POLICY_UNAVAILABLE', 'Native directory head is unavailable', 503)
            head = rows[0][0]
            if expected_head is not None and expected_head != head:
                raise ContractError('RESOURCE_VERSION_CONFLICT', 'Directory changed; restart pagination', 409)
            @contextmanager
            def snapshot(repo, commit):
                if repo != target['repo_id'] or commit != head:
                    raise ValueError('unbound directory snapshot')
                yield  # The parent authority owns repo/Branch locks until return.
            page = NativeCommitDirectoryReader(snapshot_scope=snapshot).page(
                repo_id=target['repo_id'], commit_id=head, path=target['path'], offset=offset, limit=limit)
            entries = []
            refs = page['items']
            for start in range(0, len(refs), 50):
                group = refs[start:start + 50]
                rules = authority.rules.candidates_many(group, locking=True)
                candidates = authority.shares.candidates_many(cursor, group, authority.subjects())
                for child, acl, shared in zip(group, rules, candidates):
                    decision = authority.core.evaluate_scoped(child, provider=authority.state.provider,
                        subject=authority.current_subject, rules=acl, ce_permission=authority.native_permission,
                        directory_shares=shared, attribute_allowlist=authority.preparation.contexts.allowlist,
                        hard_readonly=authority.hard_readonly)
                    if decision['visible'] and decision['read']:
                        entries.append(dict(reference=child, name=child['path'].rsplit('/', 1)[1],
                            permission='rw' if decision['write'] else 'r'))
            return dict(items=entries, head_id=head,
                next_after=None if page['next_offset'] is None else head + ':' + str(page['next_offset']))
        return authority.consume(ref, read)
