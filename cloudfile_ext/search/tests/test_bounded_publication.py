"""Run the real HTTP orchestration with native/host adapters replaced by mocks.

Legacy native grants are not covered by 4A's OIDC scope: retain both native
passes until an equivalent producer-coordinated scope is available.
"""
import importlib.util
import json
import math
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from cloudfile_ext.search.tests.test_search_access import snapshot, rule
from cloudfile_ext.search.tests.test_bounded_search import REPO, entry


@pytest.fixture
def view():
    def module(name, **attrs):
        result = ModuleType(name)
        result.__dict__.update(attrs)
        return result
    class Response(dict):
        def __init__(self, data, status=200):
            self.data, self.status_code = data, status
        def render(self):
            self.content = json.dumps(self.data).encode()
            render_hook()
            return self
    render_hook = Mock()
    class APIView:
        def get_renderer_context(self):
            return {}
    class BadSignature(Exception):
        pass
    signing = SimpleNamespace(BadSignature=BadSignature, dumps=Mock(return_value='cursor'), loads=Mock())
    api = Mock()
    api.get_repo.return_value = SimpleNamespace(head_cmmt_id='a' * 40)
    api.get_dirent_by_path.return_value = entry()
    api.check_permission_by_path.return_value = 'rw'
    # Model the wire transport separately from scalar invocations, never count
    # one RPC as one authorization decision. Native C parity is tested too.
    def many(raw):
        request = json.loads(raw)
        return json.dumps(dict(version=1, repo_id=request['repo_id'], user=request['user'],
            items=[dict(path=path, permission=api.check_permission_by_path(
                request['repo_id'], path, request['user'])) for path in request['paths']]))
    api.cf_check_permissions_many.side_effect = many
    reader = Mock(return_value=snapshot())
    modules = {
        'django.conf': module('django.conf', settings=SimpleNamespace(CF_PROVIDER_SEARCH='meilisearch')),
        'django.core': module('django.core', signing=signing),
        'rest_framework.authentication': module('rest_framework.authentication', SessionAuthentication=object),
        'rest_framework.permissions': module('rest_framework.permissions', IsAuthenticated=object),
        'rest_framework.response': module('rest_framework.response', Response=Response),
        'rest_framework.views': module('rest_framework.views', APIView=APIView),
        'seahub.api2.authentication': module('seahub.api2.authentication', TokenAuthentication=object),
        'seahub.api2.throttling': module('seahub.api2.throttling', UserRateThrottle=object),
        'seahub.utils.timeutils': module('seahub.utils.timeutils', timestamp_to_isoformat_timestr=str),
        'seaserv': module('seaserv', seafile_api=api),
        'cloudfile_ext.search.access_runtime': module('cloudfile_ext.search.access_runtime', read_snapshot=reader),
    }
    spec = importlib.util.spec_from_file_location('cloudfile_ext.search._publication_test',
        Path(__file__).parents[1] / 'bounded_view.py')
    owned = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, modules):
        spec.loader.exec_module(owned)
    client = Mock()
    owned.client_from_settings = Mock(return_value=client)
    owned.check_permission = lambda user, repo, path, native: native
    request = SimpleNamespace(GET=dict(repo_id=REPO, q='drawing', path='/a', limit='100'),
        user=SimpleNamespace(username='alice'), accepted_renderer=object(), accepted_media_type='application/json')
    yield SimpleNamespace(module=owned, api=api, reader=reader, client=client, request=request, render_hook=render_hook)


def hits(paths):
    return dict(hits=[dict(repo_id=REPO, path=path) for path in paths])


@pytest.mark.parametrize('count', [1, 20, 50, 100])
@pytest.mark.parametrize('provider', ['meilisearch', 'native'])
def test_actual_legacy_counts_and_exact_object_contract(view, count, provider):
    paths = ['/a/drawing' + str(i) for i in range(count)]
    view.client._call.return_value = hits(paths)
    if provider == 'native':
        view.module.client_from_settings.return_value = None
        view.api.list_dir_by_path.return_value = [entry(path.rsplit('/', 1)[1]) for path in paths]
    response = view.module.BoundedSearch().get(view.request)
    assert response.status_code == 200
    assert view.api.check_permission_by_path.call_count == 2 * (count + 2)
    assert view.api.cf_check_permissions_many.call_count == 1 + math.ceil(count / 50) + math.ceil((count + 2) / 50)
    assert view.reader.call_count == 3
    assert isinstance(response.content, bytes)
    assert view.api.get_dirent_by_path.call_count == (count if provider == 'meilisearch' else 0)
    assert response.data['authorization']['version'] == 1
    assert response.data['authorization']['head'] == 'a' * 40
    for item in response.data['data']:
        assert item['authorization'] == dict(repo_id=REPO, path=item['path'], kind='file', visible=True, read=True)


def test_mixed_hidden_native_and_file_denials_duplicates_and_stale_hits(view):
    value = snapshot([rule('/a/hidden', 'invisible'), rule('/a/hidden/open', 'rw'),
        rule('/a/denied.txt', 'none', inherit=False)])
    value['native_rules'] = [rule('/a/native', 'invisible')]
    view.reader.return_value = value
    view.client._call.return_value = hits(['/a/ok.txt', '/a/ok.txt', '/a/hidden/open/file.txt',
        '/a/denied.txt', '/a/native/file.txt', '/a/deleted.txt', '/a/moved.txt'])
    view.api.get_dirent_by_path.side_effect = lambda repo, path: entry() if path == '/a/ok.txt' else None
    response = view.module.BoundedSearch().get(view.request)
    assert response.status_code == 200
    assert [item['path'] for item in response.data['data']] == ['/a/ok.txt']
    assert view.api.get_dirent_by_path.call_count == 3


@pytest.mark.parametrize('change', ['native', 'policy', 'head'])
def test_revocation_or_head_change_never_publishes_authorization_contract(view, change):
    view.client._call.return_value = hits(['/a/drawing'])
    if change == 'native':
        # Initial root,parent,object allow, then revoke at publication.
        view.api.check_permission_by_path.side_effect = ['rw', 'rw', 'rw', None]
    elif change == 'policy':
        changed = snapshot([rule('/a/drawing', 'none')])
        view.reader.side_effect = [snapshot(), changed]
    else:
        view.api.get_repo.side_effect = [SimpleNamespace(head_cmmt_id='a' * 40), SimpleNamespace(head_cmmt_id='b' * 40)]
    response = view.module.BoundedSearch().get(view.request)
    assert response.status_code == 503
    assert 'data' not in response.data and 'authorization' not in response.data


def test_different_parents_use_their_own_native_decisions(view):
    view.client._call.return_value = hits(['/a/one/file', '/a/two/file'])
    view.api.check_permission_by_path.side_effect = lambda repo, path, user: None if path == '/a/two/file' else 'rw'
    response = view.module.BoundedSearch().get(view.request)
    assert response.status_code == 200
    assert [item['path'] for item in response.data['data']] == ['/a/one/file']


@pytest.mark.parametrize('mutation', ['acl', 'share', 'group', 'account'])
@pytest.mark.parametrize('stage', ['first_pass', 'metadata', 'second_pass', 'after_second', 'serialization'])
def test_mutation_discards_page_at_each_prepublication_boundary(view, mutation, stage):
    # These are deterministic state injections, not proof of a cross-writer
    # lease. Real native writer coverage is reported separately.
    value = snapshot()
    view.reader.return_value = value
    view.client._call.return_value = hits(['/a/drawing'])
    def revoke():
        if mutation == 'acl': value['rules'].append(rule('/a', 'none'))
        elif mutation == 'share': value['state']['permission'] = None
        elif mutation == 'group': value['subjects'] = [('user', 'alice')]
        else: value['state']['active'] = False
    if stage == 'metadata':
        view.api.get_dirent_by_path.side_effect = lambda *args: (revoke(), entry())[1]
    elif stage == 'serialization':
        view.render_hook.side_effect = revoke
    else:
        original = view.api.cf_check_permissions_many.side_effect
        def transport(raw):
            result = original(raw)
            call = view.api.cf_check_permissions_many.call_count
            if (stage == 'first_pass' and call == 2) or (stage in ('second_pass', 'after_second') and call == 3):
                revoke()
            return result
        view.api.cf_check_permissions_many.side_effect = transport
    response = view.module.BoundedSearch().get(view.request)
    assert response.status_code == 503
    assert 'data' not in response.data


def test_serialization_runs_before_second_native_pass(view):
    view.client._call.return_value = hits(['/a/drawing'])
    def render():
        assert view.api.cf_check_permissions_many.call_count == 2
        view.api.check_permission_by_path.return_value = None
    view.render_hook.side_effect = render
    assert view.module.BoundedSearch().get(view.request).status_code == 503


def test_partial_or_unavailable_native_batch_never_publishes(view):
    view.client._call.return_value = hits(['/a/drawing'])
    view.api.cf_check_permissions_many.side_effect = TimeoutError()
    assert view.module.BoundedSearch().get(view.request).status_code == 503


def test_real_drf_renderer_is_eager_and_finalization_does_not_render_again(view):
    # Exercise the actual DRF Response lifecycle, not only the adapter mock.
    from django.conf import settings
    if not settings.configured:
        settings.configure(DEFAULT_CHARSET='utf-8', REST_FRAMEWORK={})
    from rest_framework.response import Response
    from rest_framework.renderers import JSONRenderer
    from rest_framework.views import APIView
    renders = []
    class Renderer(JSONRenderer):
        def render(self, data, *args, **kwargs):
            renders.append(view.api.cf_check_permissions_many.call_count)
            return super().render(data, *args, **kwargs)
    view.module.Response = Response
    view.request.accepted_renderer = Renderer()
    view.client._call.return_value = hits(['/a/drawing'])
    response = view.module.BoundedSearch().get(view.request)
    assert response.status_code == 200 and response.is_rendered
    assert renders == [2]
    host = APIView()
    host.headers = {}
    finalized = host.finalize_response(view.request, response)
    finalized.render()
    assert renders == [2]
    assert json.loads(finalized.content)['data'][0]['path'] == '/a/drawing'


@pytest.mark.parametrize('failed_transport', [2, 3, 4, 5, 6])
def test_failure_in_any_candidate_or_freshness_partition_discards_page(view, failed_transport):
    # Even after successful metadata/serialization, a late partition failure
    # must replace the prepared response with an error rather than partial data.
    view.client._call.return_value = hits(['/a/drawing' + str(i) for i in range(100)])
    original = view.api.cf_check_permissions_many.side_effect
    def rpc(raw):
        if view.api.cf_check_permissions_many.call_count == failed_transport:
            raise RuntimeError('native provider failed')
        return original(raw)
    view.api.cf_check_permissions_many.side_effect = rpc
    response = view.module.BoundedSearch().get(view.request)
    assert response.status_code == 503
    assert 'data' not in response.data and 'authorization' not in response.data
