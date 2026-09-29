"""Execute the actual upstream callback against isolated native/network doubles.

Seahub's module imports require a running native Seafile installation. Extract
only its function AST so these regressions exercise production control flow
without starting that installation or reproducing the callback implementation.
"""
import ast
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from cloudfile_ext.office.idempotency import signed_payload_matches


@pytest.fixture
def callback():
    source = Path(__file__).resolve().parents[3] / 'seahub/onlyoffice/views.py'
    tree = ast.parse(source.read_text())
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                    and node.name == 'onlyoffice_editor_callback')
    function.decorator_list = []
    network_error = type('NetworkError', (Exception,), {})
    requests = SimpleNamespace(RequestException=network_error,
        get=Mock(return_value=SimpleNamespace(content=b'edited content')),
        post=Mock(return_value=SimpleNamespace(status_code=200)))
    namespace = dict(json=json, os=os, requests=requests, logger=Mock(), cache=Mock(),
        VERIFY_ONLYOFFICE_CERTIFICATE=True, HttpResponse=lambda body: json.loads(body),
        get_file_info_by_doc_key=Mock(return_value=dict(repo_id='repo', file_path='/a.docx', username='owner')),
        delete_doc_key=Mock(), seafile_api=Mock(), is_pro_version=lambda: True,
        if_locked_by_online_office=lambda *args: True,
        gen_inner_file_upload_url=lambda *args: 'https://fileserver/update')
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), 'exec'), namespace)
    return namespace


def invoke(callback, status):
    return callback['onlyoffice_editor_callback'](SimpleNamespace(method='POST', body=json.dumps(
        dict(key='document', status=status, url='https://document/save'))))


@pytest.mark.parametrize('status', [2, 6])
@pytest.mark.parametrize('failure', ['download', 'upload', 'http'])
def test_failed_publication_preserves_session(callback, status, failure):
    requests = callback['requests']
    if failure == 'http':
        requests.post.return_value.status_code = 503
    else:
        getattr(requests, 'get' if failure == 'download' else 'post').side_effect = requests.RequestException()
    assert invoke(callback, status) == {'error': 1}
    callback['delete_doc_key'].assert_not_called()
    callback['seafile_api'].unlock_file.assert_not_called()
    callback['cache'].set.assert_not_called()


@pytest.mark.parametrize('status,closed', [(2, True), (6, False), (4, True)])
def test_success_closes_only_final_session(callback, status, closed):
    assert invoke(callback, status) == {'error': 0}
    assert callback['delete_doc_key'].called is closed
    assert callback['seafile_api'].unlock_file.called is closed
    assert callback['requests'].post.called is (status != 4)


def test_signature_must_cover_callback_body():
    payload = dict(key='document', status=2, url='https://document/save')
    assert signed_payload_matches(payload, payload)
    assert signed_payload_matches({'payload': payload}, {**payload, 'token': 'jwt'})
    assert not signed_payload_matches({'sub': 'valid-but-unrelated'}, payload)
    assert not signed_payload_matches(payload, {**payload, 'url': 'https://other/save'})
    assert not signed_payload_matches(payload, {**payload, 'status': 4})


def test_signature_does_not_equate_boolean_status_with_integer():
    assert not signed_payload_matches({'status': 1}, {'status': True})


@pytest.fixture
def guarded_callback(monkeypatch):
    from django.conf import settings
    if not settings.configured:
        settings.configure(SECRET_KEY='fixture-only', ALLOWED_HOSTS=['testserver'], DEFAULT_CHARSET='utf-8')
    from cloudfile_ext.office import callbacks
    monkeypatch.setattr(callbacks, 'settings', SimpleNamespace(ONLYOFFICE_JWT_SECRET='fixture-secret' * 3))
    monkeypatch.setattr(callbacks, 'cache', Mock(get=Mock(return_value=None)))
    return callbacks


def test_guard_requires_signature_and_signed_body(guarded_callback):
    import jwt
    callbacks = guarded_callback
    payload = dict(key='document', status=2, url='https://document/save')
    token = jwt.encode(payload, callbacks.settings.ONLYOFFICE_JWT_SECRET, algorithm='HS256')
    request = SimpleNamespace(headers={'Authorization': 'Bearer ' + token})
    assert callbacks._authenticated(request, payload)
    assert not callbacks._authenticated(request, {**payload, 'status': 4})
    callbacks.settings.ONLYOFFICE_JWT_SECRET = ''
    assert not callbacks._authenticated(request, payload)


def test_guard_does_not_cache_failed_callback_or_release_checkout(guarded_callback, monkeypatch):
    import sys
    import jwt
    from django.http import HttpResponse
    callbacks = guarded_callback
    payload = dict(key='document', status=2, url='https://document/save')
    token = jwt.encode(payload, callbacks.settings.ONLYOFFICE_JWT_SECRET, algorithm='HS256')
    payload['token'] = token
    upstream = Mock(return_value=HttpResponse('{"error": 1}'))
    monkeypatch.setitem(sys.modules, 'seahub.onlyoffice.views', SimpleNamespace(onlyoffice_editor_callback=upstream))
    request = SimpleNamespace(method='POST', headers={}, body=json.dumps(payload))
    assert json.loads(callbacks.onlyoffice_callback(request).content) == {'error': 1}
    callbacks.cache.set.assert_not_called()
    upstream.return_value = HttpResponse('{"error": 0}')
    assert json.loads(callbacks.onlyoffice_callback(request).content) == {'error': 0}
    callbacks.cache.set.assert_called_once()
