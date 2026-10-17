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
        tags = tag_snapshot(repo.id)
        old_head = saved['head'] if saved else self.baseline(repo, bootstrap_before)
        if old_head is None:
            self.scan(repo, '/', tags)
        elif old_head != repo.head_cmmt_id:
            diffs = self.native.diff_commits(repo.id, old_head, repo.head_cmmt_id, 1)
            if diffs is None or len(diffs) > 10000:
                raise SearchUnavailable('native commit diff unavailable or over budget')
            for diff in diffs:
                path = normalize_path('/' + diff.name)
                if diff.status in ('del', 'deldir', 'mov'):
                    self.remove(repo.id, path)
                if diff.status == 'mov':
                    self.refresh(repo, normalize_path('/' + diff.new_name), tags)
                elif diff.status in ('add', 'mod', 'newdir'):
                    self.refresh(repo, path, tags)
                elif diff.status not in ('del', 'deldir'):
                    raise SearchUnavailable('unsupported native diff')
        previous = saved.get('tags', {}) if saved else {}
        for path in previous.keys() | tags.keys():
            if previous.get(path) != tags.get(path):
                self.refresh(repo, path, tags, subtree=False)
        current = self.native.get_repo(repo.id)
        if current is None or current.head_cmmt_id != repo.head_cmmt_id or tag_snapshot(repo.id) != tags:
            raise SearchUnavailable('native snapshot changed; retry without advancing checkpoint')
        return dict(head=repo.head_cmmt_id, tags=tags)


def tick(client, native, checkpoint, bootstrap_before=0):
    from django.db import close_old_connections
    close_old_connections()
    path = Path(checkpoint)
    state = json.loads(path.read_text()) if path.exists() else {}
    indexer, offset, present = Indexer(client, native), 0, set()
    while True:
        repos = native.get_repo_list(offset, 100)
        if repos is None:
            raise SearchUnavailable('native library list unavailable')
        for repo in repos:
            present.add(repo.id)
            if repo.is_virtual or repo.encrypted:
                continue
            try:
                state[repo.id] = indexer.reconcile(repo, state.get(repo.id), bootstrap_before)
                temporary = path.with_suffix('.tmp')
                temporary.write_text(json.dumps(state, ensure_ascii=False))
                temporary.replace(path)
            except Exception:
                logger.exception('Search index catch-up failed for library %s; checkpoint retained', repo.id)
        offset += len(repos)
        if len(repos) < 100:
            break
    # Removal only follows a complete successful native library enumeration.
    for repo_id in state.keys() - present:
        indexer.remove(repo_id, '/')
        del state[repo_id]
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(state, ensure_ascii=False))
    temporary.replace(path)


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
    with open(args.checkpoint + '.lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        while True:
            try:
                tick(configured_client(), seafile_api, args.checkpoint, args.bootstrap_before)
            except Exception:
                logger.exception('Search index worker unavailable; file services remain independent')
            if args.once:
                break
            time.sleep(60)


if __name__ == '__main__':
    main()
