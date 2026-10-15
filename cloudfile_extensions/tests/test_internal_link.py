"""Existing CE Internal Link + CloudFile scoped directory authority."""
import ast
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from cloudfile_extensions.common.errors import ContractError

REPO = '11111111-1111-4111-8111-111111111111'


def test_locator_uses_native_session_and_does_not_add_grants():
    from cloudfile_extensions.authorization.internal_link import scoped_directory_address
    from cloudfile_extensions.authorization import native_read, directory_access
    request = object()
    active = Mock(return_value=True)
    trace = {}
    @contextmanager
    def authority(value, request_id):
        assert value is request and len(request_id) == 36
        yield 'trusted-identity'
    class Service:
        def __init__(self, actor):
            assert actor == 'trusted-identity'
        def resolve(self, payload):
            trace.update(payload)
            return dict(root_path='/folder', initial_path=payload['reference']['path'], permission='r')

    with patch('django.conf.settings', SimpleNamespace(CLOUDFILE_AUTHORIZATION_ENABLED=False)), \
         patch.object(native_read, 'enabled', active), \
         patch.object(native_read, 'authority', authority), \
         patch.object(directory_access, 'DirectoryAccessService', Service):
        location = scoped_directory_address(request, REPO, '/folder/child')
    assert location == dict(root_path='/folder', initial_path='/folder/child', permission='r')
    assert trace == {'reference': dict(repo_id=REPO, path='/folder/child', kind='dir')}
    active.assert_called_once_with()


def test_hosted_and_native_authorities_fail_closed():
    from cloudfile_extensions.authorization.internal_link import scoped_directory_address
    from cloudfile_extensions.authorization import native_read, gunicorn
    @contextmanager
    def denied(*args):
        raise ContractError('ACCESS_DENIED','Permission denied',403)
        yield None

    with patch('django.conf.settings', SimpleNamespace(CLOUDFILE_AUTHORIZATION_ENABLED=True)), \
         patch.object(gunicorn, 'directory_service', denied):
        with pytest.raises(ContractError) as err:
            scoped_directory_address(object(), REPO, '/secret')
        assert err.value.status == 403

    with patch('django.conf.settings', SimpleNamespace(CLOUDFILE_AUTHORIZATION_ENABLED=False)), \
         patch.object(native_read, 'enabled', return_value=True), \
         patch.object(native_read, 'authority', denied):
        with pytest.raises(ContractError):
            scoped_directory_address(object(), REPO, '/secret')
    with patch('django.conf.settings', SimpleNamespace(CLOUDFILE_AUTHORIZATION_ENABLED=False)), \
         patch.object(native_read, 'enabled', return_value=False):
        assert scoped_directory_address(object(), REPO, '/folder') is None


def smartlink_token_class(monkeypatch, *, authorized, native_permission=None):
    import sys
    source = Path(__file__).resolve().parents[2] / 'seahub/api2/endpoints/smart_link.py'
    tree = ast.parse(source.read_text())
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'SmartLinkToken')
    native = SimpleNamespace(
        repo_id=REPO, parent_path='/folder', filename='child', is_dir=True)
    uuidmap = SimpleNamespace(objects=SimpleNamespace(get_fileuuidmap_by_uuid=lambda token: native))
    share = SimpleNamespace(
        scoped_directory_address=lambda request, repo, path: (
            dict(root_path='/folder', initial_path='/folder/child', permission='r')
            if authorized else (_ for _ in ()).throw(ContractError('ACCESS_DENIED','Denied',403))))
    monkeypatch.setitem(sys.modules, 'seahub.tags.models', SimpleNamespace(FileUUIDMap=uuidmap))
    monkeypatch.setitem(sys.modules, 'cloudfile_extensions.authorization.internal_link', share)
    check = Mock(return_value=native_permission)
    ns = dict(__name__='seahub.api2.endpoints.smart_link', APIView=object, TokenAuthentication=object,
        SessionAuthentication=object, IsAuthenticated=object, UserRateThrottle=object,
        FileUUIDMap=uuidmap, posixpath=__import__('posixpath'), check_folder_permission=check,
        Response=lambda payload: payload,
        status=SimpleNamespace(HTTP_403_FORBIDDEN=403, HTTP_503_SERVICE_UNAVAILABLE=503,
            HTTP_400_BAD_REQUEST=400),
        api_error=lambda status, message: dict(status=status, message=message))
    exec(compile(ast.Module(body=[cls], type_ignores=[]), 'smart-link', 'exec'), ns)
    return ns['SmartLinkToken'](), check


def test_existing_smart_link_uses_shared_root_not_parent_library_permission(monkeypatch):
    obj, check = smartlink_token_class(monkeypatch, authorized=True)
    result = obj.get(object(), 'a-token')
    assert result['repo_id'] == REPO and result['path'] == '/folder/child'
    assert result['root_path'] == '/folder'
    assert result['initial_path'] == '/folder/child'
    assert result['permission'] == 'r'
    # The existing CE permission is checked first; when unavailable, the
    # directory-only ACL proof is still required and is never skipped.
    check.assert_called_once()


def test_existing_smart_link_does_not_fall_back_on_scoped_denial(monkeypatch):
    obj, check = smartlink_token_class(monkeypatch, authorized=False)
    result = obj.get(object(), 'a-token')
    assert result['status'] == 403
    # The existing CE permission is checked first; when unavailable, the
    # directory-only ACL proof is still required and is never skipped.
    check.assert_called_once()


def test_plain_ce_library_preserves_original_internal_link_flow(monkeypatch):
    obj, check = smartlink_token_class(monkeypatch, authorized=False, native_permission='rw')
    result = obj.get(object(), 'a-token')
    assert result == {'repo_id': REPO, 'path': '/folder/child', 'is_dir': True}
    check.assert_called_once()


def test_full_authorization_session_receives_same_shared_directory_root():
    from cloudfile_extensions.authorization.internal_link import scoped_directory_address
    from cloudfile_extensions.authorization import gunicorn
    @contextmanager
    def service(request, request_id):
        yield SimpleNamespace(resolve_directory=lambda value: dict(
            root_path='/folder', initial_path=value['reference']['path'], permission='r'))
    with patch('django.conf.settings', SimpleNamespace(CLOUDFILE_AUTHORIZATION_ENABLED=True)), \
         patch.object(gunicorn, 'directory_service', service):
        result = scoped_directory_address(object(), REPO, '/folder/child')
    assert result['root_path'] == '/folder'


def smartlink_create_class(monkeypatch, *, scoped, native_permission):
    """Load the upstream CE view while exercising the real modified method."""
    import os
    import posixpath
    import sys
    source = Path(__file__).resolve().parents[2] / 'seahub/api2/endpoints/smart_link.py'
    module = ast.parse(source.read_text())
    cls = next(n for n in module.body if isinstance(n, ast.ClassDef) and n.name == 'SmartLink')
    native = SimpleNamespace(
        get_repo=lambda repo_id: SimpleNamespace(is_virtual=False),
        get_dir_id_by_path=lambda repo_id, path: 'c' * 40)
    maps = SimpleNamespace(objects=SimpleNamespace(
        get_or_create_fileuuidmap=Mock(return_value=SimpleNamespace(uuid='a-token'))))
    helper = Mock(side_effect=scoped) if isinstance(scoped, BaseException) else Mock(return_value=scoped)
    monkeypatch.setitem(sys.modules, 'cloudfile_extensions.authorization.internal_link',
        SimpleNamespace(scoped_directory_address=helper))
    permissions = Mock(return_value=native_permission)
    ns = dict(__name__='seahub.api2.endpoints.smart_link', APIView=object,
        TokenAuthentication=object, SessionAuthentication=object,
        IsAuthenticated=object, UserRateThrottle=object, status=SimpleNamespace(
            HTTP_400_BAD_REQUEST=400, HTTP_403_FORBIDDEN=403, HTTP_503_SERVICE_UNAVAILABLE=503,
            HTTP_404_NOT_FOUND=404, HTTP_500_INTERNAL_SERVER_ERROR=500),
        seafile_api=native, FileUUIDMap=maps,
        is_valid_repo_id_format=lambda repo: repo == REPO,
        to_python_boolean=lambda value: value == 'true',
        normalize_dir_path=lambda path: path, normalize_file_path=lambda path: path,
        posixpath=posixpath, os=os, logger=Mock(),
        check_folder_permission=permissions, gen_smart_link=lambda value: 'https://example.test/smart-link/' + value + '/',
        Response=lambda payload: payload,
        api_error=lambda code, msg: dict(status=code, message=msg))
    exec(compile(ast.Module(body=[cls], type_ignores=[]), 'smart-link-create', 'exec'), ns)
    return ns['SmartLink'](), helper, permissions, maps


def test_scoped_shared_folder_owner_can_copy_existing_seafile_link(monkeypatch):
    location = dict(root_path='/folder', initial_path='/folder/child', permission='r')
    obj, helper, permissions, maps = smartlink_create_class(
        monkeypatch, scoped=location, native_permission=None)
    req = SimpleNamespace(GET=dict(repo_id=REPO, path='/folder/child', is_dir='true'))
    result = obj.get(req)
    assert result['smart_link'] == 'https://example.test/smart-link/a-token/'
    helper.assert_called_once_with(req, REPO, '/folder/child')
    maps.objects.get_or_create_fileuuidmap.assert_called_once()
    permissions.assert_called_once()


def test_copy_link_does_not_issue_uuid_when_scoped_access_denied(monkeypatch):
    obj, helper, _, maps = smartlink_create_class(monkeypatch,
        scoped=ContractError('ACCESS_DENIED', 'Denied', 403), native_permission=None)
    response = obj.get(SimpleNamespace(GET=dict(repo_id=REPO, path='/folder/child', is_dir='true')))
    assert response['status'] == 403
    maps.objects.get_or_create_fileuuidmap.assert_not_called()


def test_copy_link_on_plain_ce_library_keeps_native_behavior(monkeypatch):
    obj, helper, _, maps = smartlink_create_class(monkeypatch,
        scoped=AssertionError('must remain CE'), native_permission='rw')
    result = obj.get(SimpleNamespace(GET=dict(repo_id=REPO, path='/folder/child', is_dir='true')))
    assert result['smart_link_token'] == 'a-token'
    helper.assert_not_called()
    maps.objects.get_or_create_fileuuidmap.assert_called_once()
