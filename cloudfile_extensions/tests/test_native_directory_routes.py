"""OAuth-native and hosted v0.9 directory read API contract parity.

Use isolated view fixtures to keep the upstream Seahub runtime out of fast
tests; SQL and native C authorization are covered by their own suites.
"""
import ast
from pathlib import Path
import re
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from cloudfile_extensions.common.errors import ContractError, invalid
from cloudfile_extensions.resources.paths import resource_ref

REPO = '11111111-1111-4111-8111-111111111111'
SOURCE = Path(__file__).resolve().parents[1] / 'authorization/native_http.py'


class Params(dict):
    def getlist(self, key):
        value = super().__getitem__(key)
        return value if isinstance(value, list) else [value]

    def __getitem__(self, key):
        value = super().__getitem__(key)
        return value[-1] if isinstance(value, list) else value

    def get(self, key, default=None):
        return self[key] if key in self else default


def view(monkeypatch, operation):
    from cloudfile_extensions.authorization import directory_access, directory_entries

    current = object()
    trace = {}
    access = SimpleNamespace(
        resolve=lambda payload: trace.update(method='resolve', payload=payload) or
            dict(reference=payload['reference'], root_path='/folder', initial_path=payload['reference']['path'], permission='r'),
        shared_with_me=lambda **params: trace.update(method='shared', params=params) or {'items': [], 'next_after': None})
    entries = SimpleNamespace(
        list=lambda payload, **params: trace.update(method='entries', payload=payload, params=params) or
            {'items': [], 'next_after': None})
    monkeypatch.setattr(directory_access, 'DirectoryAccessService', lambda value: access if value is current else None)
    monkeypatch.setattr(directory_entries, 'DirectoryEntriesService', lambda value: entries if value is current else None)

    module = ast.parse(SOURCE.read_text())
    cls = next(n for n in module.body if isinstance(n, ast.ClassDef) and n.name == 'NativeDirectoryAccessView')
    env = dict(__name__='cloudfile_extensions.authorization.native_http',
        __package__='cloudfile_extensions.authorization',
        APIView=object, TokenAuthentication=object, SessionAuthentication=object,
        IsAuthenticated=object, re=re, invalid=invalid, ContractError=ContractError,
        resource_ref=resource_ref, response=lambda request, action: action(current))
    exec(compile(ast.Module(body=[cls], type_ignores=[]), 'native-directory-routes', 'exec'), env)
    obj = env['NativeDirectoryAccessView']()
    obj.operation = operation
    return obj, trace


def request(**params):
    return SimpleNamespace(GET=Params(params), _request=SimpleNamespace(read=lambda n: b''))


def test_native_directory_address_keeps_root_and_initial_path(monkeypatch):
    obj, trace = view(monkeypatch, 'resolve')
    result = obj.get(request(repo_id=REPO, path='/folder/child', kind='dir'))
    assert result['root_path'] == '/folder'
    assert result['initial_path'] == '/folder/child'
    assert trace['payload']['reference']['repo_id'] == REPO


def test_native_shared_directory_and_pagination_use_scoped_service(monkeypatch):
    obj, trace = view(monkeypatch, 'shared')
    assert obj.get(request(limit='5', after='cursor')) == {'items': [], 'next_after': None}
    assert trace == dict(method='shared', params=dict(limit=5, after='cursor'))
    obj, trace = view(monkeypatch, 'entries')
    assert obj.get(request(repo_id=REPO, path='/folder', kind='dir', shared_root='/folder', limit='9', after='a:1')) == {
        'items': [], 'next_after': None}
    assert trace['payload']['shared_root'] == '/folder'
    assert trace['params'] == dict(limit=9, after='a:1')


@pytest.mark.parametrize('op,query', [
    ('resolve', {'repo_id':REPO, 'path':'/folder', 'kind':'dir', 'extra':'user'}),
    ('resolve', {'repo_id':REPO, 'path':'/folder', 'kind':'dir', 'shared_root':['/folder','/']}),
    ('shared', {'repo_id':REPO}),
    ('shared', {'limit':'101'}),
    ('shared', {'limit':'0'}),
    ('entries', {'repo_id':REPO, 'path':'/folder', 'kind':'dir', 'limit':'999'}),
    ('entries', {'repo_id':REPO, 'path':'/folder'}),
])
def test_native_directory_rejects_invalid_query_before_authorization(monkeypatch, op, query):
    obj, trace = view(monkeypatch, op)
    with pytest.raises(ContractError) as error:
        obj.get(request(**query))
    assert error.value.status == 400
    assert trace == {}


def test_native_directory_rejects_get_with_body(monkeypatch):
    obj, trace = view(monkeypatch, 'resolve')
    req = request(repo_id=REPO, path='/folder', kind='dir')
    req._request.read = lambda n: b'bad'
    with pytest.raises(ContractError):
        obj.get(req)
    assert trace == {}
