"""Maintain the existing derived index from native commit diffs and CE Tags.

Checkpoints are disposable local JSON; native CE tags remain the only source of truth. Initial catch-up of an existing
index requires an explicit timestamp preceding the runtime cutover. Missing
libraries are scanned with fixed-commit directory pages; existing indexes are
neither cleared nor globally rebuilt.
"""
import argparse
import fcntl
import hashlib
import json
import logging
import os
from pathlib import Path
import posixpath
import stat
import time

from .client import SearchUnavailable, normalize_path
from .documents import ancestor_paths

logger = logging.getLogger(__name__)


def doc_id(repo_id, path):
    return repo_id + '-' + hashlib.sha1(path.encode('utf-8')).hexdigest()


def confirm(client, task):
    uid = task.get('taskUid') if isinstance(task, dict) else None
    if type(uid) is not int or uid < 0:
        raise SearchUnavailable('missing index task')
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        result = client.call('GET', '/tasks/' + str(uid))
        if result.get('uid') != uid or result.get('indexUid') != client.index_path.rsplit('/', 1)[-1]:
            raise SearchUnavailable('index task mismatch')
        if result.get('status') == 'succeeded':
            return
        if result.get('status') not in ('enqueued', 'processing'):
            raise SearchUnavailable('index task failed')
        time.sleep(.2)
    raise SearchUnavailable('index task timed out')


TAG_SWEEP_ITEMS = 200


def tag_labels(repo_id, references):
    """Read current CE labels for exactly the requested visible file/dir refs."""
    if not references:
        return {}
    from cloudfile_ext.v2.tag_reads import read
    try:
        records = read(repo_id, references)
        return {path: sorted({tag['tag_name'] for tag in records[(path, kind)]})
                for path, kind in references}
    except Exception as error:
        raise SearchUnavailable('native tag read unavailable') from error


class Indexer:
    def __init__(self, client, native):
        self.client, self.native = client, native

    def remove(self, repo_id, path):
        predicate = 'repo_id = ' + json.dumps(repo_id)
        if path != '/':
            predicate += ' AND (path = ' + json.dumps(path, ensure_ascii=False) + ' OR dirs IN ' + json.dumps([path], ensure_ascii=False) + ')'
        confirm(self.client, self.client.call('POST', self.client.index_path + '/documents/delete', {'filter': predicate}))

    def upsert(self, repo, path, entry, tags):
        directory = stat.S_ISDIR(entry.mode)
        name = posixpath.basename(path)
        return dict(id=doc_id(repo.id, path), repo_id=repo.id, path=path, name=name,
                    object_type='dir' if directory else 'file', size=0 if directory else entry.size,
                    mtime=entry.mtime, extension=name.rsplit('.', 1)[-1].lower() if not directory and '.' in name else '',
                    tags=tags.get(path, [None, []])[1], dirs=ancestor_paths(path), content='')

    def publish(self, documents):
        if documents:
            confirm(self.client, self.client.call('PUT', self.client.index_path + '/documents', documents))

    def scan(self, repo, root):
        pending, documents = [root], []
        while pending:
            parent, offset = pending.pop(), 0
            while True:
                entries = self.native.list_dir_by_commit_and_path(repo.id, repo.head_cmmt_id, parent, offset, 200)
                if entries is None:
                    raise SearchUnavailable('native directory snapshot unavailable')
                refs = []
                for entry in entries:
                    path = normalize_path(posixpath.join(parent, entry.obj_name))
                    if stat.S_ISDIR(entry.mode):
                        pending.append(path)
                        kind = 'dir'
                    elif stat.S_ISREG(entry.mode):
                        kind = 'file'
                    else:
                        raise SearchUnavailable('unsupported native object')
                    refs.append((path, kind))
                tags = tag_labels(repo.id, refs)
                for entry, (path, _) in zip(entries, refs):
                    documents.append(self.upsert(repo, path, entry, {path: [None, tags[path]]}))
                    if len(documents) == 200:
                        self.publish(documents)
                        documents = []
                offset += len(entries)
                if len(entries) < 200:
                    break
        self.publish(documents)

    def scan_slice(self, repo, progress, max_pages=10):
        """Index at most max_pages native directory windows from one fixed HEAD.

        The caller checkpoints the resulting stack only after Meili confirms
        every upsert. Replaying a batch after a crash is safe: doc IDs are
        deterministic. No whole-library traversal in one background tick.
        """
        head, pending = progress.get('head'), progress.get('pending')
        if (not isinstance(head, str) or len(head) != 40 or
                any(c not in '0123456789abcdef' for c in head) or
                not isinstance(pending, list) or len(pending) > 10000 or
                type(max_pages) is not int or not 1 <= max_pages <= 100):
            raise SearchUnavailable('invalid initial index checkpoint')
        scanned = 0
        while pending and scanned < max_pages:
            frame = pending[-1]
            if not isinstance(frame, dict) or set(frame) != {'path', 'offset'}:
                raise SearchUnavailable('invalid initial index frame')
            parent, offset = normalize_path(frame['path']), frame['offset']
            if type(offset) is not int or not 0 <= offset <= 2147483447:
                raise SearchUnavailable('invalid initial index offset')
            entries = self.native.list_dir_by_commit_and_path(repo.id, head, parent, offset, 200)
            if entries is None or len(entries) > 200:
                raise SearchUnavailable('native directory snapshot unavailable')
            documents, subdirs, seen = [], [], set()
            refs = []
            for entry in entries:
                name = getattr(entry, 'obj_name', None)
                if (not isinstance(name, str) or not name or name in ('.', '..') or
                        '/' in name or '\\' in name):
                    raise SearchUnavailable('invalid native directory name')
                if name in seen:
                    raise SearchUnavailable('duplicate native entry name')
                seen.add(name)
                child = normalize_path(posixpath.join(parent, name))
                if stat.S_ISDIR(entry.mode):
                    subdirs.append(child)
                    kind = 'dir'
                elif stat.S_ISREG(entry.mode):
                    kind = 'file'
                else:
                    raise SearchUnavailable('unsupported native object')
                refs.append((child, kind))
            tags = tag_labels(repo.id, refs)
            for entry, (child, _) in zip(entries, refs):
                documents.append(self.upsert(repo, child, entry, {child: [None, tags[child]]}))
            self.publish(documents)
            # Mutate the stack only after the async Meilisearch task is
            # confirmed. On failure the next run can safely repeat the page.
            pending.pop()
            if len(entries) == 200:
                pending.append(dict(path=parent, offset=offset + 200))
            pending.extend(dict(path=child, offset=0) for child in reversed(subdirs))
            if len(pending) > 10000:
                raise SearchUnavailable('initial index traversal too wide')
            scanned += 1
        return not pending

    def refresh(self, repo, path, subtree=True):
        entry = self.native.get_dirent_by_path(repo.id, path)
        if entry is None:
            self.remove(repo.id, path)
            return
        if not (stat.S_ISDIR(entry.mode) or stat.S_ISREG(entry.mode)):
            raise SearchUnavailable('unsupported native object')
        kind = 'dir' if stat.S_ISDIR(entry.mode) else 'file'
        tags = tag_labels(repo.id, [(path, kind)])
        self.publish([self.upsert(repo, path, entry, {path: [None, tags[path]]})])
        if subtree and kind == 'dir':
            self.scan(repo, path)

    def sweep(self, repo, after):
        """Keyset-scan at most 200 sparse native UUID rows per repo per tick.

        No full-library tag snapshot and no upper bound on library file count.
        Retaining native FileUUIDMap rows allows later passes to clear deleted
        tag labels. Search remains eventually consistent.
        """
        from seahub.tags.models import FileUUIDMap
        if not isinstance(after, str) or len(after) > 36:
            raise SearchUnavailable('invalid native tag cursor')
        query = FileUUIDMap.objects.filter(repo_id=repo.id)
        if after:
            query = query.filter(uuid__gt=after)
        page = list(query.order_by('uuid').values_list(
            'uuid', 'parent_path', 'filename', 'is_dir')[:TAG_SWEEP_ITEMS])
        if not page:
            return ''
        refs = [(normalize_path(posixpath.join(parent, filename)),
                 'dir' if is_dir else 'file')
                for _, parent, filename, is_dir in page]
        labels = tag_labels(repo.id, refs)
        documents = []
        for path, kind in refs:
            entry = self.native.get_dirent_by_path(repo.id, path)
            if entry is None:
                self.remove(repo.id, path)
                continue
            actual = 'dir' if stat.S_ISDIR(entry.mode) else 'file'
            if actual != kind or not (stat.S_ISDIR(entry.mode) or stat.S_ISREG(entry.mode)):
                raise SearchUnavailable('native tag target changed kind')
            documents.append(self.upsert(repo, path, entry, {path: [None, labels[path]]}))
        self.publish(documents)
        return str(page[-1][0])

    def baseline(self, repo, timestamp):
        probe = self.client.call('POST', self.client.index_path + '/documents/fetch',
                                 {'filter': 'repo_id = ' + json.dumps(repo.id), 'limit': 1, 'fields': ['id']})
        if not probe['results']:
            return None
        if not timestamp:
            raise SearchUnavailable('existing index needs an explicit bootstrap-before timestamp')
        for offset in range(0, 10000, 100):
            commits = self.native.get_commit_list(repo.id, offset, 100)
            if commits is None:
                raise SearchUnavailable('native commit history unavailable')
            for commit in commits:
                if commit.ctime <= timestamp:
                    return commit.id
            if len(commits) < 100:
                return None
        raise SearchUnavailable('bootstrap commit budget exceeded')

    def reconcile(self, repo, saved, bootstrap_before):
        saved = saved or {}
        old_head = saved.get('head') or self.baseline(repo, bootstrap_before)
        if old_head is None:
            self.scan(repo, '/')
            cursor = ''
        else:
            if old_head != repo.head_cmmt_id:
                diffs = self.native.diff_commits(repo.id, old_head, repo.head_cmmt_id, 1)
                if diffs is None or len(diffs) > 10000:
                    raise SearchUnavailable('native commit diff unavailable or over budget')
                for diff in diffs:
                    path = normalize_path('/' + diff.name)
                    if diff.status in ('del', 'deldir', 'mov'):
                        self.remove(repo.id, path)
                    if diff.status == 'mov':
                        self.refresh(repo, normalize_path('/' + diff.new_name))
                    elif diff.status in ('add', 'mod', 'newdir'):
                        self.refresh(repo, path)
                    elif diff.status not in ('del', 'deldir'):
                        raise SearchUnavailable('unsupported native diff')
            # Tag mutations do not necessarily produce native commits.
            # The cursor only advances after Meilisearch acknowledges the page.
            cursor = self.sweep(repo, saved.get('tag_cursor', ''))
        current = self.native.get_repo(repo.id)
        if current is None or current.head_cmmt_id != repo.head_cmmt_id:
            raise SearchUnavailable('native head changed; tag cursor stays unchanged')
        return dict(head=repo.head_cmmt_id, tag_cursor=cursor)


def tick(client, native, checkpoint, bootstrap_before=0, pages_per_repo=10):
    """One bounded pass across repos, with a durable initial-scan cursor.

    Existing libraries retain the commit-diff/tag-sweep mechanism. New large
    libraries get at most pages_per_repo directory windows per round, resuming
    at the exact pinned commit even after a worker restart.
    """
    from django.db import close_old_connections
    close_old_connections()
    if type(pages_per_repo) is not int or not 1 <= pages_per_repo <= 100:
        raise SearchUnavailable('invalid indexing page budget')
    path = Path(checkpoint)
    state = json.loads(path.read_text()) if path.exists() else {}
    if not isinstance(state, dict):
        raise SearchUnavailable('invalid search checkpoint')
    indexer, offset, present = Indexer(client, native), 0, set()

    def persist():
        temporary = path.with_suffix('.tmp')
        temporary.write_text(json.dumps(state, ensure_ascii=False))
        temporary.replace(path)

    while True:
        repos = native.get_repo_list(offset, 100)
        if repos is None:
            raise SearchUnavailable('native library list unavailable')
        for repo in repos:
            present.add(repo.id)
            if repo.is_virtual or repo.encrypted:
                continue
            try:
                saved = state.get(repo.id)
                if saved is not None and not isinstance(saved, dict):
                    raise SearchUnavailable('invalid per-library index checkpoint')
                if not saved or (not saved.get('head') and 'initial' not in saved):
                    old_head = indexer.baseline(repo, bootstrap_before)
                    if old_head is None:
                        saved = {'initial': {'head': repo.head_cmmt_id,
                                             'pending': [{'path': '/', 'offset': 0}]}}
                        state[repo.id] = saved
                        persist()  # Must survive a crash before the first page.
                    else:
                        saved = {'head': old_head, 'tag_cursor': ''}
                if 'initial' in saved:
                    initial = saved['initial']
                    complete = indexer.scan_slice(repo, initial, pages_per_repo)
                    if complete:
                        # The scan used this fixed historic commit. If HEAD
                        # advanced during it, next tick catches up by diff.
                        state[repo.id] = dict(head=initial['head'], tag_cursor='')
                    persist()
                    continue
                state[repo.id] = indexer.reconcile(repo, saved, bootstrap_before)
                persist()
            except Exception:
                logger.exception('Search index catch-up failed for library %s; checkpoint retained', repo.id)
        offset += len(repos)
        if len(repos) < 100:
            break
    # Only a complete native library enumeration can certify deletion.
    for repo_id in state.keys() - present:
        indexer.remove(repo_id, '/')
        del state[repo_id]
    persist()



def main():
    import django
    django.setup()
    from seaserv import seafile_api
    from .http import configured_client
    parser = argparse.ArgumentParser()
    parser.add_argument('--checkpoint', required=True)
    parser.add_argument('--once', action='store_true')
    parser.add_argument('--bootstrap-before', type=int, default=int(os.environ.get('CF_SEARCH_BOOTSTRAP_BEFORE', '0')))
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    os.umask(0o077)
    from django.conf import settings
    interval = max(15, int(getattr(settings, 'CF_SEARCH_INDEX_INTERVAL', 60)))
    with open(args.checkpoint + '.lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        while True:
            started = time.monotonic()
            try:
                tick(configured_client(), seafile_api, args.checkpoint,
                     args.bootstrap_before, pages_per_repo=10)
                logger.info('CF_SEARCH_INDEX status=OK duration_ms=%d',
                            int((time.monotonic() - started) * 1000))
            except Exception:
                logger.exception('CF_SEARCH_INDEX status=FAILED; file services remain independent')
            if args.once:
                break
            time.sleep(interval)


if __name__ == '__main__':
    main()
