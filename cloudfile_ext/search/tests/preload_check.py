"""Real-model check: preloaded tag maps equal the per-path lookups.

Run in a subprocess by test_tag_preload.py, mirroring
cloudfile_ext/legacy_tags/tests/orm_check.py: an isolated SQLite schema keeps
the real ORM managers under test without touching the shared Django settings
the pytest session already loaded. Prints a JSON summary on success; a failed
assertion exits non-zero with the SQL/values that disagreed.
"""
import posixpath
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from django.conf import settings

settings.configure(
    INSTALLED_APPS=['seahub.repo_tags', 'seahub.tags', 'seahub.file_tags'],
    DATABASES={'default': dict(ENGINE='django.db.backends.sqlite3', NAME=':memory:')},
    SECRET_KEY='preload-check', DEFAULT_AUTO_FIELD='django.db.models.AutoField',
    DEFAULT_CHARSET='utf-8')


def module(name, **values):
    result = ModuleType(name)
    result.__dict__.update(values)
    return result


api = Mock()
api.get_repo.return_value = SimpleNamespace(is_virtual=False, head_cmmt_id='a' * 40)
sys.modules['seahub'] = module(
    'seahub', __path__=[str(Path(__file__).resolve().parents[3] / 'seahub')])
sys.modules['seaserv'] = module('seaserv', seafile_api=api)
# Only path normalization is stubbed (same bodies as seahub.utils); the tag
# models and managers stay the real ones.
sys.modules['seahub.utils'] = module(
    'seahub.utils',
    normalize_file_path=lambda p: '/' + p.strip('/') if p.strip('/') else '',
    normalize_dir_path=lambda p: '/' + p.strip('/') + '/' if p.strip('/') else '/')

import django  # noqa: E402
django.setup()  # noqa: E402

from django.db import connection  # noqa: E402
from django.test.utils import CaptureQueriesContext  # noqa: E402
from seahub.file_tags.models import FileTags  # noqa: E402
from seahub.repo_tags.models import RepoTags  # noqa: E402
from seahub.tags.models import FileTag, FileUUIDMap, Tags  # noqa: E402
from cloudfile_ext.search.indexer import (  # noqa: E402
    _fetch_directory_tags, _fetch_tags, preload_tags,
)

REPO = '11111111-1111-4111-8111-111111111111'
VIRTUAL = '33333333-3333-4333-8333-333333333333'
ORIGIN = '44444444-4444-4444-8444-444444444444'

with connection.schema_editor() as schema:
    for model in (FileUUIDMap, Tags, FileTag, RepoTags, FileTags):
        schema.create_model(model)


def seed_file(path, repo_id=REPO, names=()):
    parent, name = posixpath.split(path.rstrip('/'))
    uuid_map = FileUUIDMap.objects.create(
        repo_id=repo_id, parent_path=parent, filename=name, is_dir=False)
    for tag_name in names:
        repo_tag = RepoTags.objects.create(repo_id=repo_id, name=tag_name, color='#fff')
        FileTags.objects.create(file_uuid=uuid_map, repo_tag=repo_tag)


def seed_dir(path, repo_id=REPO, names=()):
    parent, name = posixpath.split(path.rstrip('/'))
    uuid_map = FileUUIDMap.objects.create(
        repo_id=repo_id, parent_path=parent, filename=name, is_dir=True)
    for tag_name in names:
        FileTag.objects.create(uuid=uuid_map, tag=Tags.objects.create(name=tag_name),
                               username='alice')


# Files keep the lookup's insertion order; directories are sorted/deduplicated.
seed_file('/top.txt', names=('root-file',))
seed_file('/a/tagged.txt', names=('z-last', 'a-first'))
seed_file('/a/untagged.txt')
# A file and a directory bound to the same path never cross over.
seed_file('/clash', names=('file-side',))
seed_dir('/clash', names=('dir-side',))
seed_dir('/folder', names=('z-last', 'a-first'))
seed_dir('/folder/child')
seed_dir('/empty')

file_tags, dir_tags = preload_tags(REPO)
assert file_tags == {
    '/top.txt': ['root-file'],
    '/a/tagged.txt': ['z-last', 'a-first'],
    '/clash': ['file-side'],
}, file_tags
assert dir_tags == {'/clash': ['dir-side'], '/folder': ['a-first', 'z-last']}, dir_tags

# Every path, tagged or not, answers exactly what the per-path lookup returns.
for path in ('/top.txt', '/a/tagged.txt', '/a/untagged.txt', '/clash', '/missing.txt'):
    assert file_tags.get(path, []) == _fetch_tags(REPO, path), (path, file_tags.get(path))
for path in ('/folder', '/folder/child', '/empty', '/clash', '/missing'):
    assert dir_tags.get(path, []) == _fetch_directory_tags(REPO, path), (path, dir_tags.get(path))

with CaptureQueriesContext(connection) as queries:
    preload_tags(REPO)
selects = [q['sql'] for q in queries if q['sql'].lstrip().upper().startswith('SELECT')]
assert len(selects) == 3, selects

# Virtual library: tags live on the origin repo under the origin path, which is
# exactly the rewrite FileUUIDMapManager applies to a per-path lookup.
seed_file('/origin/inside/f.txt', repo_id=ORIGIN, names=('virtual-tag',))
seed_file('/origin/other/g.txt', repo_id=ORIGIN, names=('other-tag',))
seed_dir('/origin/inside/d', repo_id=ORIGIN, names=('virtual-dir',))
api.get_repo.return_value = SimpleNamespace(
    is_virtual=True, origin_repo_id=ORIGIN, origin_path='/origin/inside')
virtual_files, virtual_dirs = preload_tags(VIRTUAL)
assert virtual_files == {'/f.txt': ['virtual-tag']}, virtual_files
assert virtual_dirs == {'/d': ['virtual-dir']}, virtual_dirs
assert virtual_files.get('/f.txt', []) == _fetch_tags(VIRTUAL, '/f.txt')
assert virtual_files.get('/g.txt', []) == _fetch_tags(VIRTUAL, '/g.txt') == []
assert virtual_dirs.get('/d', []) == _fetch_directory_tags(VIRTUAL, '/d')

print('preload_check ok: file_rows=%d dir_rows=%d preload_selects=%d' % (
    len(file_tags), len(dir_tags), len(selects)))
