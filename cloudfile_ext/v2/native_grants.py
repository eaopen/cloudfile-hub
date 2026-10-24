"""Native CE library share adapter for the standard CloudFile B-mode API.

Only CE user/group repo shares; directory ACL remains in the existing
DirectoryRules endpoint. No new permissions table, publisher identity or ACL
truth. Client account names never imply trusted business UID/administrator.
"""
from .acl_policy import PolicyError
from .acl_store import RevisionConflict

MAX_GRANTS = 4096


class NativeGrantUnavailable(Exception):
    """A native CE read/write or post-write readback could not be confirmed."""


def owner_group(owner):
    """Group id when the library is owned by a group, else None.

    CE/Pro group-owned libraries are listed by Seafile's own share APIs as a
    group grant to the owning group. That row is ownership, not a removable
    grant: Seahub's share listings filter it out of the visible shares and no
    r/rw management API may revoke it.
    """
    if not isinstance(owner, str) or not owner.endswith('@seafile_group'):
        return None
    head = owner.split('@', 1)[0]
    if not head.isdigit() or not 1 <= int(head) <= 2147483647:
        return None
    return int(head)


def target(kind, value):
    if kind == 'user':
        if (not isinstance(value, str) or not 1 <= len(value) <= 255
                or value != value.strip() or '@' not in value
                or any(ord(c) < 33 or ord(c) == 127 for c in value)):
            raise PolicyError('invalid native CE user account')
        return value
    if kind == 'group':
        if type(value) is not int or not 1 <= value <= 2147483647:
            raise PolicyError('invalid native CE group id')
        return value
    raise PolicyError('invalid native share subject type')


def permission(value, *, allow_none=False):
    if value in ('r', 'rw') and type(value) is str:
        return value
    if allow_none and value is None:
        return None
    raise PolicyError('only native r/rw library grants supported')


class NativeLibraryGrants:
    def __init__(self, api, repo_id, *, user_exists, group_exists, protected_admin):
        self.api, self.repo_id = api, repo_id
        self.user_exists, self.group_exists = user_exists, group_exists
        self.protected_admin = protected_admin

    def snapshot(self):
        owner = self.api.get_repo_owner(self.repo_id)
        if not isinstance(owner, str) or not owner:
            raise NativeGrantUnavailable('native CE library owner unavailable')
        users = self.api.list_repo_shared_to(owner, self.repo_id)
        groups = self.api.list_repo_shared_group_by_user(owner, self.repo_id)
        if not isinstance(users, (list, tuple)) or not isinstance(groups, (list, tuple)):
            raise NativeGrantUnavailable('native CE library shares unavailable')
        if len(users) + len(groups) > MAX_GRANTS:
            raise NativeGrantUnavailable('native share list exceeds safe limit')
        owning_group = owner_group(owner)
        rows = {}
        for kind, shares in (('user', users), ('group', groups)):
            for item in shares:
                try:
                    subject = target(kind, item.user if kind == 'user' else item.group_id)
                    level = permission(item.perm)
                except (AttributeError, PolicyError) as error:
                    raise NativeGrantUnavailable('malformed native CE share record') from error
                if kind == 'group' and subject == owning_group:
                    # The owning group is group ownership, not a grant this
                    # API may list as revocable or modify.
                    continue
                key = (kind, subject)
                if key in rows:
                    raise NativeGrantUnavailable('duplicate native CE grant')
                rows[key] = level
        return owner, rows

    def list(self):
        owner, rows = self.snapshot()
        return {'repo_id': self.repo_id, 'owner': owner, 'source': 'seafile-ce',
                'grants': [
                    {'subject_type': kind, 'subject': value, 'permission': level}
                    for (kind, value), level in sorted(
                        rows.items(), key=lambda item: (item[0][0], str(item[0][1])))
                ]}

    def change(self, kind, subject, *, expected, desired):
        """Optimistic read/check, one CE RPC, then exact native readback.

        Unlike cf_dir_acl transaction CAS, native CE share RPCs are not
        compare-and-swap. This is best-effort concurrency detection only;
        operators avoid conflicting writers as documented in Hub #57.
        """
        subject = target(kind, subject)
        expected = permission(expected, allow_none=True)
        desired = permission(desired, allow_none=True)
        owner, rows = self.snapshot()
        if kind == 'user' and subject == owner:
            raise PolicyError('cannot share a library to its native owner')
        if kind == 'group' and subject == owner_group(owner):
            raise PolicyError('cannot modify the owning group of a group library')
        before = rows.get((kind, subject))
        if before != expected:
            raise RevisionConflict()
        if before == desired:
            # A verified no-op is idempotent even when CE also carries a
            # separate library-admin marker. No share RPC or admin change.
            return {'repo_id': self.repo_id, 'subject_type': kind,
                    'subject': subject, 'permission': desired, 'changed': False}
        if before is not None and self.protected_admin(kind, subject):
            # CE's separate library-admin marker must not be changed or
            # silently revoked by this r/rw-only management API.
            raise PolicyError('native library admin share requires CE admin API')
        if desired is not None:
            if kind == 'user' and not self.user_exists(subject):
                raise PolicyError('native user unavailable')
            if kind == 'group' and not self.group_exists(subject):
                raise PolicyError('native group unavailable')
        if kind == 'user':
            if desired is None:
                self.api.remove_share(self.repo_id, owner, subject)
            elif before is None:
                self.api.share_repo(self.repo_id, owner, subject, desired)
            else:
                self.api.set_share_permission(self.repo_id, owner, subject, desired)
        else:
            if desired is None:
                self.api.unset_group_repo(self.repo_id, subject, owner)
            elif before is None:
                self.api.set_group_repo(self.repo_id, subject, owner, desired)
            else:
                self.api.set_group_repo_permission(subject, self.repo_id, desired)
        _, refreshed = self.snapshot()
        if refreshed.get((kind, subject)) != desired:
            raise NativeGrantUnavailable('native library grant readback mismatch')
        return {'repo_id': self.repo_id, 'subject_type': kind,
                'subject': subject, 'permission': desired, 'changed': True}
