"""Run actual native entry functions with isolated CE imports; no database or deployment claim."""
import ast
import inspect
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from cloudfile_ext.v2.share_links import require_external_sharing

ROOT = Path(__file__).resolve().parents[3]


class ClosedLink(Exception):
    pass


def native_function(file, name, scope=None):
    tree = ast.parse((ROOT / file).read_text())
    parts = name.split('.')
    nodes = tree.body
    for part in parts:
        node = next(n for n in nodes if isinstance(n, (ast.ClassDef, ast.FunctionDef)) and n.name == part)
        nodes = node.body
    node.decorator_list = []
    namespace = dict(scope or {})
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(ROOT / file), 'exec'), namespace)
    return namespace[node.name]


class ShareBoundariesTest(unittest.TestCase):
    def setUp(self):
        self.enabled = True
        self.modules = patch.dict(sys.modules, {
            'cloudfile_ext.features': SimpleNamespace(is_enabled=lambda key: self.enabled),
            'django.http': SimpleNamespace(Http404=ClosedLink),
        })
        self.modules.start()
        self.addCleanup(self.modules.stop)

    def test_existing_switch_is_the_only_gate(self):
        with self.assertRaises(ClosedLink):
            require_external_sharing()
        self.enabled = False
        require_external_sharing()

    def test_closed_entries_stop_before_database_rpc_or_file_access(self):
        entries = {
            'seahub/share/models.py': ['FileShareManager._add_file_share',
                'FileShareManager._get_valid_file_share_by_token',
                'UploadLinkShareManager.create_upload_link_share',
                'UploadLinkShareManager.get_valid_upload_link_by_token',
                'check_share_link_common', 'check_share_link_access_by_scope'],
            'seahub/api2/views.py': ['FileSharedLinkView.put'],
            'seahub/api2/endpoints/internal_api.py': ['InternalCheckShareLinkAccess.post', 'CheckShareLinkThumbnailAccess.post'],
            'seahub/share/views.py': ['save_shared_link', 'ajax_get_link_email_audit_code'],
            'seahub/api2/endpoints/share_links.py': ['ShareLinks.post', 'ShareLink.put',
                'ShareLinkOnlineOfficeLock.put', 'ShareLinkUploadDone.post',
                'ShareLinkSaveFileToRepo.post', 'ShareLinkSaveItemsToRepo.post',
                'ShareLinkRepoTags.get', 'ShareLinkRepoTagsTaggedFiles.get'],
            'seahub/api2/endpoints/upload_links.py': ['UploadLinks.post', 'UploadLink.put', 'UploadLinkUpload.get'],
        }
        for file, names in entries.items():
            for name in names:
                with self.subTest(entry=name):
                    function = native_function(file, name)
                    required = [None for p in inspect.signature(function).parameters.values()
                                if p.default is inspect.Parameter.empty]
                    with self.assertRaises(ClosedLink):
                        function(*required)

    def test_file_directory_and_collection_page_wrapper_denies_before_lookup(self):
        decorator = native_function('seahub/share/decorators.py', 'share_link_audit')
        view = Mock()
        with self.assertRaises(ClosedLink):
            decorator(view)(None, 'abc')
        view.assert_not_called()

    def test_owner_only_metadata_reads_even_when_sharing_is_closed(self):
        for file, klass, model, formatter in [
            ('seahub/api2/endpoints/share_links.py', 'ShareLink', 'FileShare', 'get_share_link_info'),
            ('seahub/api2/endpoints/upload_links.py', 'UploadLink', 'UploadLinkShare', 'get_upload_link_info'),
        ]:
            link = SimpleNamespace(username='owner', is_owner=lambda username: username == 'owner')
            format_info = Mock(return_value={'has_password': True, 'password': None})
            fn = native_function(file, klass + '.get', {
                model: SimpleNamespace(objects=SimpleNamespace(get=lambda **kw: link), DoesNotExist=KeyError),
                formatter: format_info, 'Response': lambda value: value,
                'api_error': lambda status, message: status,
                'status': SimpleNamespace(HTTP_404_NOT_FOUND=404),
            })
            for enabled in [False, True]:
                self.enabled = enabled
                format_info.reset_mock()
                self.assertEqual(fn(None, SimpleNamespace(user=SimpleNamespace(username='other')), 'abc'), 404)
                format_info.assert_not_called()
                self.assertEqual(fn(None, SimpleNamespace(user=SimpleNamespace(username='owner')), 'abc')['has_password'], True)

    def test_detail_serializers_never_decrypt_passwords(self):
        import os
        link = SimpleNamespace(token='abc', repo_id='repo', path='/file', s_type='f',
            expire_date=None, ctime=None, username='owner', show_download_link=True,
            view_cnt=0, is_expired=lambda: False, get_permissions=lambda: {},
            is_encrypted=lambda: True, user_scope='all_users', description='',
            get_password=Mock(side_effect=AssertionError('must not decrypt')))
        for file, name in [
            ('seahub/api2/endpoints/share_links.py', 'get_share_link_info'),
            ('seahub/api2/endpoints/upload_links.py', 'get_upload_link_info'),
        ]:
            fn = native_function(file, name, {
                'os': os, 'seafile_api': SimpleNamespace(get_repo=lambda repo: None),
                'gen_shared_link': lambda *args: 'url', 'gen_file_get_url_by_sharelink': lambda *args: 'url',
                'gen_shared_upload_link': lambda *args: 'url',
            })
            body = fn(link)
            self.assertIsNone(body['password'])
            self.assertTrue(body['has_password'])
        link.get_password.assert_not_called()

    def test_native_repository_deletes_bind_token_to_url_repo(self):
        cases = [
            ('seahub/api2/views.py', 'RepoDownloadSharedLink', 'FileShare'),
            ('seahub/api2/views.py', 'RepoUploadSharedLink', 'UploadLinkShare'),
            ('seahub/api2/endpoints/repo_share_links.py', 'RepoShareLink', 'FileShare'),
            ('seahub/api2/endpoints/repo_upload_links.py', 'RepoUploadLink', 'UploadLinkShare'),
        ]
        for file, klass, model in cases:
            link = SimpleNamespace(repo_id='actual', path='/file', delete=Mock())
            def lookup(**kwargs):
                if kwargs != {'token': 'abc', 'repo_id': 'actual'}:
                    raise KeyError()
                return link
            fn = native_function(file, klass + '.delete', {
                model: SimpleNamespace(objects=SimpleNamespace(get=lookup), DoesNotExist=KeyError),
                'get_repo': lambda repo: SimpleNamespace(is_virtual=False),
                'is_org_context': lambda request: False,
                'seafile_api': SimpleNamespace(get_repo_owner=lambda repo: 'owner'),
                'is_repo_admin': lambda username, repo: True,
                'api_error': lambda status, msg: status,
                'status': SimpleNamespace(HTTP_404_NOT_FOUND=404),
                'Response': lambda data: data,
            })
            request = SimpleNamespace(user=SimpleNamespace(username='owner'))
            self.assertEqual(fn(None, request, 'wrong', 'abc'), 404)
            link.delete.assert_not_called()
            self.assertTrue(fn(None, request, 'actual', 'abc')['success'])
            link.delete.assert_called_once()

    def test_unrestricted_password_check_retains_native_semantics(self):
        self.enabled = False
        check = native_function('seahub/share/models.py', 'check_share_link_common', {
            'check_share_link_access': lambda *args: False,
            'check_password': lambda password, stored: password == 'correct',
            'set_share_link_access': Mock(), '_': lambda text: text,
        })
        link = SimpleNamespace(is_encrypted=lambda: True, token='abc', password='hash', get_password=lambda: None)
        request = SimpleNamespace(method='POST', POST={'password': 'wrong'})
        self.assertFalse(check(request, link)[0])
        request.POST['password'] = 'correct'
        self.assertTrue(check(request, link)[0])
        self.enabled = True
        with self.assertRaises(ClosedLink):
            check(request, link)


if __name__ == '__main__':
    unittest.main()
