"""Exercise the native HTTP adapter with authority boundaries kept explicit."""
import ast
import stat
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from cloudfile_extensions.common.errors import ContractError, invalid
from cloudfile_extensions.resources.paths import resource_ref

REPO = '11111111-1111-4111-8111-111111111111'
HEAD = 'a' * 40
DIR = 'b' * 40


def adapter(monkeypatch, entries, *, decisions=None, denied=False):
    api = SimpleNamespace(get_dir_id_by_commit_and_path=Mock(return_value=DIR),
        list_dir_by_commit_and_path=Mock(return_value=entries))
    import sys
    monkeypatch.setitem(sys.modules, 'seaserv', SimpleNamespace(seafile_api=api))
    cursor = Mock()
    cursor.fetchall.return_value = ((HEAD,),)
    core = Mock()
    core.evaluate_scoped.side_effect = decisions or [dict(visible=True, read=True, write=False)] * len(entries)
    current = SimpleNamespace(core=core, state=SimpleNamespace(provider='etech'),
        current_subject={}, native_permission='r', hard_readonly=False,
        effective_access={'read': True, 'write': False},
        preparation=SimpleNamespace(contexts=SimpleNamespace(allowlist=())),
        subjects=lambda: [], rules=Mock(), shares=Mock())
    current.rules.candidates_many.side_effect = lambda refs, **kwargs: [[] for _ in refs]
    current.shares.candidates_many.side_effect = lambda cursor, refs, subjects: [[] for _ in refs]
    def consume(ref, reader):
        if denied:
            raise ContractError('ACCESS_DENIED', 'Denied', 403)
        return reader(cursor, ref)
    current.consume = consume
    tree = ast.parse((Path(__file__).parents[1] / 'authorization/native_http.py').read_text())
    fn = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'directory_page')
    env = dict(re=__import__('re'), stat=stat, resource_ref=resource_ref, ContractError=ContractError,
        invalid=invalid, response=lambda request, operation: operation(current))
    exec(compile(ast.Module(body=[fn], type_ignores=[]), 'native-http', 'exec'), env)
    return lambda **query: env['directory_page'](SimpleNamespace(GET=query), REPO), api, current


def entry(name):
    return SimpleNamespace(obj_name=name, obj_id='c' * 40, mode=stat.S_IFDIR, size=0, mtime=1)


def test_denied_parent_does_not_read_objects(monkeypatch):
    page, api, _ = adapter(monkeypatch, [entry('private')], denied=True)
    with pytest.raises(ContractError) as error:
        page()
    assert error.value.status == 403
    api.list_dir_by_commit_and_path.assert_not_called()


def test_hidden_page_keeps_continuation_without_names(monkeypatch):
    page, api, current = adapter(monkeypatch, [entry('private'), entry('next')],
        decisions=[dict(visible=False, read=False, write=False)])
    result = page(limit='1')
    assert result['dirent_list'] == []
    assert result['has_more'] is True and result['next_start'] == 1
    assert result['acl_enforced'] is True
    api.list_dir_by_commit_and_path.assert_called_once_with(REPO, HEAD, '/', 0, 2)


def test_visible_entry_uses_effective_permission(monkeypatch):
    page, _, _ = adapter(monkeypatch, [entry('visible')])
    result = page()
    assert result['dirent_list'][0]['permission'] == 'r'
    assert result['dirent_list'][0]['name'] == 'visible'
    assert result['has_more'] is False


def test_revision_conflict_is_not_empty_success(monkeypatch):
    page, api, _ = adapter(monkeypatch, [])
    with pytest.raises(ContractError) as error:
        page(if_dir_id='d' * 40)
    assert error.value.status == 409
    api.list_dir_by_commit_and_path.assert_not_called()


@pytest.mark.parametrize('query', [dict(limit='501'), dict(start='-1'), dict(recursive='1'),
    dict(with_parents='true'), dict(with_thumbnail='true')])
def test_unsupported_or_unbounded_reads_rejected(monkeypatch, query):
    page, api, _ = adapter(monkeypatch, [])
    with pytest.raises(ContractError):
        page(**query)
    api.list_dir_by_commit_and_path.assert_not_called()


def test_bad_native_result_fails_closed(monkeypatch):
    page, _, _ = adapter(monkeypatch, [entry('../private')])
    with pytest.raises(ContractError) as error:
        page()
    assert error.value.status == 503


def test_capability_requires_verified_runtime():
    from cloudfile_extensions.capabilities import native_read_implementation_registry, build_capability_document
    from cloudfile_extensions.registry import registry
    assert native_read_implementation_registry(registry, ready=lambda: False) is registry
    value = native_read_implementation_registry(registry, ready=lambda: True)
    caps = build_capability_document(implementation_registry=value)['capabilities']
    assert caps['directory.acl']['enabled'] is True
    assert caps['directory.acl.effective']['enabled'] is True
    assert caps['auth.oidc']['enabled'] is False
    assert caps['transfer.web']['enabled'] is False


def test_native_authentication_rejects_inactive_before_resources(monkeypatch):
    from cloudfile_extensions.authorization import native_read
    monkeypatch.setattr(native_read, 'enabled', lambda: True)
    storage = Mock(side_effect=AssertionError('must not allocate authority'))
    monkeypatch.setattr(native_read, 'NativeAdministratorResources', storage)
    for authenticated, active in [(False, True), (True, False)]:
        request = SimpleNamespace(user=SimpleNamespace(is_authenticated=authenticated, is_active=active))
        with pytest.raises(ContractError) as error:
            with native_read.authority(request, 'test'):
                pytest.fail('invalid user entered authority')
        assert error.value.status == 401
    storage.assert_not_called()


def test_existing_directory_requires_exact_business_identity_and_ancestors():
    from cloudfile_extensions.authorization.native_read import ExistingDirectoryProvider, ATTRIBUTES
    from datetime import datetime, timezone
    provider = object.__new__(ExistingDirectoryProvider)
    provider.attribute_allowlist = ATTRIBUTES
    valid = dict(userId='417137619324108800', status='active', attributes={'employee_no': 'admin'},
        organizations=[], roles=[], organization_ancestors=[], etag='test',
        generated_at=datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'))
    provider.directory = SimpleNamespace(context_for_user_id=Mock(return_value=valid))
    assert provider.fetch(valid['userId'])['attributes']['employee_no'] == 'admin'
    # Similar display names/employee numbers cannot substitute for a stable UID.
    with pytest.raises(ContractError):
        provider.fetch('9')
    provider.directory.context_for_user_id.return_value = {k: v for k, v in valid.items() if k != 'organization_ancestors'}
    with pytest.raises(ContractError):
        provider.fetch(valid['userId'])
