"""One trusted authority for Hub and native file service decisions."""
import logging
import posixpath
import stat
from dataclasses import asdict, astuple

from django.conf import settings
from django.db import connection, transaction
from django.utils.module_loading import import_string

from . import library_cache
from .acl_policy import Principal, Decision, PolicyError, Rule, canonical_path, resolve
from .acl_store import ACLStore, uuid
from .schema import identifier

NAMESPACE = 'cf-acl-rules-v1'
# Native directory pages, matching v0.9 and the EAP items-page bounds.
PAGE_LIMIT_MAX = 500
PAGE_START_MAX = 2147483647 - PAGE_LIMIT_MAX - 1
logger = logging.getLogger(__name__)
_warned_local_cache = set()



class ACLUnavailable(Exception):
    pass


class DirectoryChanged(ACLUnavailable):
    """The path no longer resolves to the directory object being paged."""


def store():
    from seahub.utils.db_api import SeafileDB
    changed = lambda repo_id: transaction.on_commit(lambda: invalidate_library(repo_id))
    return ACLStore(connection, SeafileDB().db_name, transaction.atomic, changed)


def cache_ttl():
    try:
        ttl = library_cache.ttl('CF_ACL_CACHE_TTL', 180)
    except ValueError:
        raise ACLUnavailable('invalid ACL cache TTL') from None
    # A local invalidation cannot reach other workers. Never retain ACL grants
    # across requests in process-local or non-persistent Django cache backends.
    backend = settings.CACHES.get('default', {}).get('BACKEND', '') if settings.configured else ''
    if backend.rsplit('.', 1)[-1] in ('LocMemCache', 'DummyCache'):
        if ttl and backend not in _warned_local_cache:
            logger.warning('CloudFile ACL cache is %s: cross-request caching disabled', backend)
            _warned_local_cache.add(backend)
        return 0
    return ttl


def invalidate_library(repo_id):
    library_cache.invalidate(NAMESPACE, repo_id)


def _decode_rules(repo_id):
    def decode(rows):
        rules = tuple(Rule(*row) for row in rows)
        if any(rule.repo_id != repo_id for rule in rules):
            raise ValueError('foreign cached ACL row')
        return rules
    return decode


def library_rules(rules, repo_id, ttl):
    """All sparse rules of one library, or None over the shared budget
    (callers then read per-directory candidates). SQL failure denies."""
    return library_cache.snapshot(NAMESPACE, repo_id, ttl, lambda: rules.library(repo_id),
                                  lambda rows: [astuple(rule) for rule in rows], _decode_rules(repo_id))


def subject_adapter(config):
    from .subject_adapter import InvalidSubjectAdapter, selected_adapter
    try:
        return selected_adapter(config)
    except InvalidSubjectAdapter as error:
        raise ACLUnavailable(str(error)) from error

def current_principal(username):
    from seaserv import ccnet_api
    from seahub.profile.models import Profile
    from seahub.utils.db_api import SeafileDB
    from seahub.utils.ccnet_db import get_ccnet_db_name
    account = ccnet_api.get_emailuser(username)
    if account is None or not account.is_active:
        raise PermissionError('inactive account')
    profile = Profile.objects.get_profile_by_user(username)
    uid = profile.login_id if profile else None
    adapter = subject_adapter(settings)

    # CE-only installation has no enterprise membership. System accounts also
    # remain native even when an enterprise Directory is configured. Neither
    # case can match provider-scoped enterprise rules; in particular, a numeric
    # CE login_id is NOT proof of membership in an external directory.
    if adapter is None or not uid or uid == 'cfadmin':
        return Principal('native-local', username, frozenset())
    provider, ensure = adapter

    # A configured Directory owns *all* other external UIDs, including strings
    # with letters. Missing subjects and expired memberships fail closed; never
    # treat a non-numeric UID as a native user with broader CE access.
    import_string(ensure)(uid, username)
    schema = identifier(SeafileDB().db_name)
    accounts = identifier(get_ccnet_db_name())
    with connection.cursor() as cursor:
        cursor.execute('SELECT m.subject_type,m.namespace,m.external_id FROM ' + schema + '.cf_sso_group_map m JOIN ' +
                       accounts + '.GroupUser gu ON gu.group_id=m.group_id WHERE m.provider=%s AND gu.user_name=%s LIMIT 4097',
                       [provider, username])
        groups = cursor.fetchall()
        if len(groups) > 4096 or any(row[0] not in ('org', 'role', 'dept', 'group') for row in groups):
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
        self._virtual = {}
        self._versions = {}
        self._decisions = {}
        self._native = {}
        self._library = {}
        self._rule_paths = {}

    def _rules(self, repo_id, directory):
        if repo_id not in self._library:
            rows = library_rules(self.store, repo_id, cache_ttl())
            # One shared library snapshot for both read and write checks.
            # Per-request path buckets avoid rescanning every rule per child
            # of a large directory page; these are NOT another Redis cache.
            matched = None if rows is None else [r for r in rows if self.principal.matches(r)]
            self._library[repo_id] = matched
            if matched is not None:
                buckets = {}
                for rule in matched:
                    buckets.setdefault(rule.path, []).append(rule)
                self._rule_paths[repo_id] = buckets
        if self._library[repo_id] is None:
            return [r for r, _ in self.store.candidates(repo_id, directory, self.principal)]
        from .acl_policy import ancestors
        buckets = self._rule_paths[repo_id]
        return [rule for path in ancestors(directory) for rule in buckets.get(path, ())]

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
                origin = uuid(repo.origin_repo_id)
                root = canonical_path(repo.origin_path)
                if origin == repo_id:
                    raise ACLUnavailable('invalid native virtual repository mapping')
                original = self.api.get_repo(origin)
                if original is None or original.is_virtual:
                    raise ACLUnavailable('native origin repository unavailable')
                self._virtual[repo_id] = (origin, root)
            status = self.api.get_repo_status(repo_id)
            if status not in (-1, 0, 1):
                raise ACLUnavailable('unknown repository status')
            if repo_id in self._virtual:
                origin_status = self.api.get_repo_status(self._virtual[repo_id][0])
                if origin_status not in (-1, 0, 1):
                    raise ACLUnavailable('unknown origin repository status')
                if origin_status == 1:
                    status = 1
            self._repos[repo_id] = status
            # Validated only where it matters (page scans fail closed on unknown).
            self._versions[repo_id] = getattr(repo, 'version', None)
        key = (repo_id, directory)
        decision = self._decisions.get(key)
        if decision is None:
            # Native library grants are read live once per request; only the
            # sparse rule rows are shared across requests.
            if repo_id not in self._native:
                base = self.api.check_permission(repo_id, self.username)
                if base == 'admin':
                    base = 'rw'
                elif base in (None, 'none', 'invisible'):
                    base = None
                elif base not in ('r', 'rw'):
                    raise ACLUnavailable('unknown native permission')
                self._native[repo_id] = base
            if repo_id in self._virtual:
                # CE supplies both the sharing grant and the origin mapping.
                # Never qualify access to a virtual library via an origin ACL
                # alone, or expose origin paths in virtual-library responses.
                origin, root = self._virtual[repo_id]
                if self._native[repo_id] is None:
                    decision = Decision('invisible', None, False)
                else:
                    mapped = posixpath.join(root, directory.lstrip('/')).rstrip('/') or '/'
                    access = resolve(origin, mapped, self.principal, self._native[repo_id],
                                     self._rules(origin, mapped))
                    decision = Decision(access.permission, '/', access.from_rule)
            else:
                decision = resolve(repo_id, directory, self.principal, self._native[repo_id],
                                   self._rules(repo_id, directory))
            self._decisions[key] = decision
        # Hard native repository status is still checked once per request.
        if self._repos[repo_id] == 1 and decision.can_write:
            return Decision('r', decision.qualified_root, decision.from_rule)
        return decision

    def library_view(self, repo_id):
        """Inputs every decision in this library depends on, besides the principal.

        rules lists this principal's rows; None when the library is over the
        snapshot budget and decisions read per-directory candidates instead.
        """
        self.effective(repo_id, '/')
        if repo_id in self._virtual:
            # Virtual paths must be checked after native origin translation.
            return dict(native=self._native[repo_id], status=self._repos[repo_id], rules=None)
        self._rules(repo_id, '/')
        rules = self._library[repo_id]
        return dict(native=self._native[repo_id], status=self._repos[repo_id],
                    rules=None if rules is None else tuple(rules))

    def page(self, repo_id, path, *, start, limit, if_dir_id=None):
        """One raw native window of a directory object, filtered by this authority.

        The cursor counts native entries, not visible ones, so a window whose
        children are all hidden is an empty page that may still have more.
        """
        if (type(start) is not int or not 0 <= start <= PAGE_START_MAX or
                type(limit) is not int or not 1 <= limit <= PAGE_LIMIT_MAX):
            raise PolicyError('invalid page')
        decision = self.effective(repo_id, path)
        if not decision.can_read:
            raise PermissionError()
        directory_id = self.api.get_dir_id_by_path(repo_id, path)
        if not directory_id:
            raise FileNotFoundError()
        if if_dir_id is not None and if_dir_id != directory_id:
            raise DirectoryChanged('directory changed; restart paging')
        version = self._versions[repo_id]
        if type(version) is not int or version < 0:
            raise ACLUnavailable('unknown repository version')
        if version == 0:
            # Native list_dir skips v0 dirents with invalid ids inside the
            # window, so a short window cannot prove the end. Page the whole
            # object instead: positions stay stable for one directory id.
            every = self.api.list_dir_by_dir_id(repo_id, directory_id, -1, -1)
            children, more = every[start:start + limit], len(every) > start + limit
        else:
            # Version >= 1 JSON dir objects reject an invalid dirent id when
            # loaded (fs-mgr.c parse_dirent), so that skip cannot shorten a
            # window and one extra entry is an exact end-of-scan probe.
            children = self.api.list_dir_by_dir_id(repo_id, directory_id, start, limit + 1)
            if len(children) > limit + 1:
                raise ACLUnavailable('native directory window exceeded')
            children, more = children[:limit], len(children) > limit
        # Independently evaluate each child. Hidden children never become
        # navigation corridors or expose metadata.
        visible = []
        for entry in children:
            if not entry.obj_name or '/' in entry.obj_name or entry.obj_name in ('.', '..'):
                raise ACLUnavailable('invalid native directory entry')
            child = posixpath.join(path, entry.obj_name)
            kind = 'dir' if stat.S_ISDIR(entry.mode) else 'file'
            access = self.effective(repo_id, child, kind)
            if access.can_read:
                visible.append((entry, child, kind, access.permission))
        if self.api.get_dir_id_by_path(repo_id, path) != directory_id:
            raise DirectoryChanged('directory changed during listing')
        return dict(parent=decision, dir_id=directory_id, items=visible, scanned_count=len(children),
                    next_start=start + limit if more else None)

    def entries(self, repo_id, path, *, offset=0, limit=50):
        if type(offset) is not int or not 0 <= offset <= 1000000 or type(limit) is not int or not 1 <= limit <= 100:
            raise PolicyError('invalid page')
        page = self.page(repo_id, path, start=offset, limit=limit)
        result = [dict(repo_id=repo_id, path=child, name=entry.obj_name, kind=kind, permission=permission)
                  for entry, child, kind, permission in page['items']]
        return dict(data=result, root_path=page['parent'].qualified_root, next_offset=page['next_start'])

    def shared_roots(self):
        roots = sorted({(r.repo_id, r.path) for r, _ in self.store.shared(self.principal)})
        result = []
        for repo_id, path in roots:
            decision = self.effective(repo_id, path)
            if decision.can_read and self.api.get_dir_id_by_path(repo_id, path):
                result.append(dict(repo_id=repo_id, path=path, **asdict(decision)))
        return result


def protected(repo_id, repo):
    """Served from the library rule snapshot; a virtual repo also checks its origin.

    Over-budget libraries count as protected. SQL/RPC failure raises (denies).
    """
    uuid(repo_id)
    if repo is None:
        raise ACLUnavailable('repository unavailable')
    libraries = [repo_id]
    if repo.is_virtual:
        libraries.append(uuid(repo.origin_repo_id))
    rules, ttl = store(), cache_ttl()
    for library in libraries:
        rows = library_rules(rules, library, ttl)
        if rows is None or rows:
            return True
    return False
