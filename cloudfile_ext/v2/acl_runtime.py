"""One trusted authority for Hub and native file service decisions."""
import posixpath
import stat
import hashlib
import json
import time
from dataclasses import asdict

from django.conf import settings
from django.db import connection, transaction
from django.utils.module_loading import import_string

from .acl_policy import Principal, Decision, PolicyError, canonical_path, resolve, within
from .acl_store import ACLStore, uuid
from .schema import identifier


class ACLUnavailable(Exception):
    pass


def store():
    from seahub.utils.db_api import SeafileDB
    return ACLStore(connection, SeafileDB().db_name, transaction.atomic)


def current_principal(username):
    from seaserv import ccnet_api
    from seahub.profile.models import Profile
    from seahub.utils.db_api import SeafileDB
    from seahub.utils.ccnet_db import get_ccnet_db_name
    account = ccnet_api.get_emailuser(username)
    if account is None or not account.is_active:
        raise PermissionError('inactive account')
    profile = Profile.objects.get(user=username)
    uid = profile.login_id
    provider = getattr(settings, 'CF_ACL_PROVIDER', '')
    ensure = getattr(settings, 'CF_ACL_SUBJECT_ENSURE', '')
    if not uid or not provider or not ensure:
        raise ACLUnavailable('trusted current subject adapter unavailable')
    # Work package A supplies a server-configured callable (uid, username).
    # Success means Memberships.ensure() completed; client claims are never used.
    import_string(ensure)(uid, username)
    schema = identifier(SeafileDB().db_name)
    accounts = identifier(get_ccnet_db_name())
    with connection.cursor() as cursor:
        cursor.execute('SELECT m.subject_type,m.namespace,m.external_id FROM ' + schema + '.cf_sso_group_map m JOIN ' +
                       accounts + '.GroupUser gu ON gu.group_id=m.group_id WHERE m.provider=%s AND gu.user_name=%s LIMIT 4097',
                       [provider, username])
        groups = cursor.fetchall()
    if len(groups) > 4096 or any(row[0] not in ('org', 'role') for row in groups):
        raise ACLUnavailable('invalid current membership')
    return Principal(provider, uid, frozenset(groups))


class Authority:
    def __init__(self, username, *, principal=None, rules=None, api=None):
        self.username = username
        self.principal = current_principal(username) if principal is None else principal
        self.store = store() if rules is None else rules
        if api is None:
            from seaserv import seafile_api
            api = seafile_api
        self.api = api
        self._repos = {}
        self._decisions = {}
        self._native = {}

    def _cache(self, repo_id, directory):
        # Reuse Seahub's cache; an unavailable cache is only a performance miss.
        # Permission/auth/SQL failure still denies. No cache ledger or new table.
        ttl = getattr(settings, 'CF_ACL_CACHE_TTL', 60) if settings.configured else 0
        if type(ttl) is not int or not 0 <= ttl <= 300:
            raise ACLUnavailable('invalid ACL cache TTL')
        principal = self.principal
        scope = [self.username, principal.provider, principal.uid, sorted(principal.groups),
                 principal.active, principal.ready, repo_id, directory]
        key = 'cf-acl-v1:' + hashlib.sha256(json.dumps(scope, ensure_ascii=True).encode()).hexdigest()
        return key, ttl

    @staticmethod
    def _cached(key, ttl, directory):
        if not ttl:
            return None
        from django.core.cache import cache
        try:
            value = cache.get(key)
            if not isinstance(value, dict) or set(value) != {'expires', 'decision'}:
                return None
            now = time.time()
            if not now < value['expires'] <= now + ttl:
                return None
            decision = Decision(**value['decision'])
            if decision.permission not in ('r', 'rw', 'none', 'invisible') or type(decision.from_rule) is not bool:
                return None
            if decision.qualified_root is not None:
                canonical_path(decision.qualified_root)
                if not within(directory, decision.qualified_root):
                    return None
            elif decision.can_read:
                return None
            return decision
        except Exception:
            return None

    @staticmethod
    def _remember(key, ttl, decision):
        if ttl:
            from django.core.cache import cache
            try:
                cache.set(key, {'expires': time.time() + ttl, 'decision': asdict(decision)}, timeout=ttl)
            except Exception:
                pass

    def effective(self, repo_id, path, kind='dir'):
        uuid(repo_id)
        canonical_path(path)
        if kind not in ('dir', 'file') or (kind == 'file' and path == '/'):
            raise PolicyError('invalid object kind')
        directory = posixpath.dirname(path) if kind == 'file' else path
        if repo_id not in self._repos:
            repo = self.api.get_repo(repo_id)
            if repo is None:
                raise PermissionError('missing repository')
            if repo.is_virtual:
                raise ACLUnavailable('virtual repository scope unavailable')
            status = self.api.get_repo_status(repo_id)
            if status not in (-1, 0, 1):
                raise ACLUnavailable('unknown repository status')
            self._repos[repo_id] = status
        key, ttl = self._cache(repo_id, directory)
        decision = self._decisions.get(key) or self._cached(key, ttl, directory)
        if decision is None:
            if repo_id not in self._native:
                base = self.api.check_permission(repo_id, self.username)
                self._native[repo_id] = 'rw' if base == 'admin' else base or None
            base = self._native[repo_id]
            rules = self.store.candidates(repo_id, directory, self.principal)
            decision = resolve(repo_id, directory, self.principal, base, [r for r, _ in rules])
            self._remember(key, ttl, decision)
        self._decisions[key] = decision
        # Hard native repository status is still checked once per request and
        # is never promoted by a cached positive directory rule.
        if self._repos[repo_id] == 1 and decision.can_write:
            return Decision('r', decision.qualified_root, decision.from_rule)
        return decision

    def entries(self, repo_id, path, *, offset=0, limit=50):
        if type(offset) is not int or not 0 <= offset <= 1000000 or type(limit) is not int or not 1 <= limit <= 100:
            raise PolicyError('invalid page')
        decision = self.effective(repo_id, path)
        if not decision.can_read:
            raise PermissionError()
        # Bound native enumeration, then independently evaluate each child.
        # Hidden children never become navigation corridors or expose metadata.
        directory_id = self.api.get_dir_id_by_path(repo_id, path)
        if not directory_id:
            raise FileNotFoundError()
        children = self.api.list_dir_by_dir_id(repo_id, directory_id, offset, limit + 1)
        result = []
        for entry in children[:limit]:
            if not entry.obj_name or '/' in entry.obj_name or entry.obj_name in ('.', '..'):
                raise ACLUnavailable('invalid native directory entry')
            child = posixpath.join(path, entry.obj_name)
            kind = 'dir' if stat.S_ISDIR(entry.mode) else 'file'
            access = self.effective(repo_id, child, kind)
            if access.can_read:
                result.append(dict(repo_id=repo_id, path=child, name=entry.obj_name, kind=kind,
                                   permission=access.permission))
        if self.api.get_dir_id_by_path(repo_id, path) != directory_id:
            raise ACLUnavailable('directory changed during listing')
        return dict(data=result, root_path=decision.qualified_root,
                    next_offset=offset + limit if len(children) > limit else None)

    def shared_roots(self):
        roots = sorted({(r.repo_id, r.path) for r, _ in self.store.shared(self.principal)})
        result = []
        for repo_id, path in roots:
            decision = self.effective(repo_id, path)
            if decision.can_read and self.api.get_dir_id_by_path(repo_id, path):
                result.append(dict(repo_id=repo_id, path=path, **asdict(decision)))
        return result


def protected(repo_id):
    from seahub.utils.db_api import SeafileDB
    uuid(repo_id)
    schema = identifier(SeafileDB().db_name)
    with connection.cursor() as cursor:
        cursor.execute('SELECT EXISTS(SELECT 1 FROM ' + schema + '.cf_dir_acl WHERE repo_id=%s OR repo_id IN '
                       '(SELECT origin_repo FROM ' + schema + '.VirtualRepo WHERE repo_id=%s))', [repo_id, repo_id])
        row = cursor.fetchone()
    if row is None:
        raise ACLUnavailable('ACL storage unavailable')
    return bool(row[0])
