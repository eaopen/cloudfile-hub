# -*- coding: utf-8 -*-
"""Scanner behaviour that must remain runnable without a Django database."""

import sys
import types

from cloudfile_ext.external_sources import scanner
from cloudfile_ext.external_sources.providers import SourceError


class Entry(object):

    def __init__(self, name, is_dir=False, size=1, mtime=1):
        self.name = name
        self.is_dir = is_dir
        self.size = size
        self.mtime = mtime


class Source(object):
    id = 7
    repo_id = 'f1234567-1234-1234-1234-123456789abc'
    name = 'NAS'
    root_path = '/shared/external/nas'


class States(object):

    def __init__(self, state=None):
        self.state = state
        self.saved = []

    def get_state(self, source_id):
        return self.state

    def save_state(self, source_id, cursor_path, status, detail=''):
        self.state = types.SimpleNamespace(source_id=source_id,
                                           cursor_path=cursor_path,
                                           status=status, detail=detail)
        self.saved.append(self.state)
        return self.state


class Client(object):

    def __init__(self):
        self.deleted = []
        self.documents = []

    def delete_by_repo(self, repo_id):
        self.deleted.append(repo_id)

    def upsert_documents(self, documents):
        self.documents.extend(documents)


def _install_models(monkeypatch, states):
    models = types.ModuleType('cloudfile_ext.external_sources.models')
    models.ExternalScanState = types.SimpleNamespace(objects=states)
    monkeypatch.setitem(sys.modules, models.__name__, models)


def test_scanner_persists_a_bounded_breadth_first_queue(monkeypatch):
    states = States()
    _install_models(monkeypatch, states)
    client = Client()
    tree = {
        '/': [Entry('one.txt'), Entry('child', is_dir=True)],
        '/child': [Entry('two.txt')],
    }
    backend = types.SimpleNamespace(list_dir=lambda root, path: tree[path])
    monkeypatch.setattr(scanner.service, 'backend_for', lambda source: backend)
    monkeypatch.setattr(scanner, '_doc_id', lambda repo_id, path: repo_id + path)

    assert scanner.scan_source(Source(), client, dirs_per_tick=1, files_per_tick=10)
    assert client.deleted == [Source.repo_id]
    assert [doc['path'] for doc in client.documents] == ['/one.txt']
    assert states.state.status == 'running'

    assert scanner.scan_source(Source(), client, dirs_per_tick=1, files_per_tick=10)
    assert [doc['path'] for doc in client.documents] == ['/one.txt', '/child/two.txt']
    assert states.state.status == 'complete'


def test_scanner_error_retries_its_existing_queue_without_deleting(monkeypatch):
    states = States(types.SimpleNamespace(status='error', detail='{"queue": ["/lost"]}'))
    _install_models(monkeypatch, states)
    client = Client()

    def unavailable(root, path):
        raise SourceError('nas is offline')

    backend = types.SimpleNamespace(list_dir=unavailable)
    monkeypatch.setattr(scanner.service, 'backend_for', lambda source: backend)

    assert not scanner.scan_source(Source(), client)
    assert client.deleted == []
    assert states.state.status == 'error'
