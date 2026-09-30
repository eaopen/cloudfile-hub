"""Execute current endpoint code and optionally the actual compiled native RPC.

AST loading replaces Django/services only; no copied endpoint paging algorithm.
The Linux native runner sets CF_DIR_PAGE_TEST_LIBRARY for cross-layer cases.
"""
import ast
from contextlib import nullcontext
import importlib.util
import json
import logging
from pathlib import Path
import os
import stat
from types import SimpleNamespace, MethodType
import unittest
from unittest.mock import Mock, patch

from cloudfile_ext.directory_page import (read_directory_page, DirectoryPageError,
                                         DirectoryRevisionChanged)

ROOT = Path(__file__).resolve().parents[2]
REVISION = 'a' * 40


class Response:
    def __init__(self, data, status=200):
        self.data, self.status_code = data, status
        self.headers = {}

    def __setitem__(self, name, value):
        self.headers[name] = value


class Stars:
    def filter(self, **kwargs): return self
    def __iter__(self): return iter(())


def endpoint(api):
    source = ast.parse((ROOT / 'seahub/api2/endpoints/dir.py').read_text())
    helper = next(n for n in source.body if isinstance(n, ast.FunctionDef) and n.name == 'get_dir_file_info_list')
    view = next(n for n in source.body if isinstance(n, ast.ClassDef) and n.name == 'DirView')
    get = next(n for n in view.body if isinstance(n, ast.FunctionDef) and n.name == 'get')
    get.decorator_list = []
    view.body, view.bases, view.decorator_list = [get], [], []
    stars = Stars()
    env = dict(seafile_api=api, read_directory_page=read_directory_page,
               DirectoryPageError=DirectoryPageError, DirectoryRevisionChanged=DirectoryRevisionChanged,
               settings=SimpleNamespace(), stat=stat, posixpath=__import__('posixpath'),
               logger=Mock(),
               status=SimpleNamespace(HTTP_400_BAD_REQUEST=400, HTTP_403_FORBIDDEN=403,
                   HTTP_404_NOT_FOUND=404, HTTP_409_CONFLICT=409,
                   HTTP_500_INTERNAL_SERVER_ERROR=500, HTTP_503_SERVICE_UNAVAILABLE=503),
               api_error=lambda code, message: Response({'error_msg': message}, code), Response=Response,
               normalize_dir_path=lambda path: path.rstrip('/') or '/',
               check_folder_permission=lambda *args: 'rw' if api.parent_read else None,
               to_python_boolean=lambda value: value == 'true', THUMBNAIL_DEFAULT_SIZE=64,
               UserStarredFiles=SimpleNamespace(objects=stars),
               RepoMetadata=SimpleNamespace(objects=SimpleNamespace(filter=lambda **kwargs: SimpleNamespace(first=lambda: None))),
               PERMISSION_READ='r', PERMISSION_INVISIBLE='invisible', ENABLE_THUMBNAIL_SERVER=False,
               IMAGE='image', PDF='pdf', SVG='svg', EPUB='epub',
               is_favorites_id_enabled=lambda: False, is_pro_version=lambda: False,
               get_files_tags_in_dir=lambda *args, **kwargs: {},
               email2nickname=lambda value: value, email2contact_email=lambda value: value)
    exec(compile(ast.Module(body=[helper, view], type_ignores=[]), 'current-dir.py', 'exec'), env)
    return env['DirView']()


class API:
    revision = REVISION
    parent_read = True
    def get_repo(self, repo): return SimpleNamespace(id=repo)
    def get_dir_id_by_path(self, *args): return self.revision
    def get_repo_status(self, repo): return 0


def request(view, start=0, limit=3, **query):
    return view.get(SimpleNamespace(GET=dict(start=str(start), limit=str(limit), **query),
                                   user=SimpleNamespace(username='user')),
                    '11111111-1111-4111-8111-111111111111')


def wire(**changes):
    return json.dumps({**dict(dir_revision=REVISION, scanned_count=3, scan_exhausted=False,
                             next_scan_position=3, visible_count=0, visible_items=[]), **changes})


def native_item(**changes):
    # Mirror all fields actually emitted by dirent_to_json; minimal endpoint
    # dictionaries would now conceal missing-field contract violations.
    return {**dict(obj_id=REVISION, obj_name='directory', mode=stat.S_IFDIR,
                   version=1, mtime=0, size=0, modifier=None, permission='rw',
                   is_locked=False, lock_owner=None, lock_time=0, is_shared=False),
            **changes}


class HubEnvelopeTest(unittest.TestCase):
    def test_empty_nonterminal_page_and_diagnostics(self):
        api = API(); api.cf_list_dir_page = Mock(return_value=wire())
        with self.assertLogs('cloudfile_ext.directory_page', level='DEBUG') as logs:
            response = request(endpoint(api))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['dirent_list'], [])
        self.assertTrue(response.data['has_more'])
        self.assertEqual(response.data['next_start'], 3)
        self.assertEqual(response.data['dir_id'], REVISION)
        self.assertEqual(response.data['scanned_count'], 3)
        self.assertFalse(response.data['scan_exhausted'])
        for metric in ('scanned_count=3', 'visible_count=0', 'next_cursor=3', 'scan_exhausted=False'):
            self.assertIn(metric, logs.output[0])
        self.assertEqual(api.cf_list_dir_page.call_args.args[-2:], (0, 3))

    def test_missing_rpc_and_malformed_envelope_are_503_not_exhaustion(self):
        api = API()
        self.assertEqual(request(endpoint(api)).status_code, 503)
        for raw in ('[]', '{}', 'not-json', wire(next_scan_position=0), wire(scanned_count=True),
                    wire(scan_exhausted=True), wire(dir_revision='b' * 40), wire(visible_count=1)):
            with self.subTest(raw=raw):
                api.cf_list_dir_page = Mock(return_value=raw)
                self.assertEqual(request(endpoint(api)).status_code, 503)

    def test_rpc_revision_conflict_and_existing_precheck_are_409(self):
        api = API(); api.cf_list_dir_page = Mock(return_value=json.dumps({'error': 'DIR_REVISION_CHANGED'}))
        self.assertEqual(request(endpoint(api)).status_code, 409)
        api.cf_list_dir_page.reset_mock()
        self.assertEqual(request(endpoint(api), 3, if_dir_id='b' * 40).status_code, 409)
        api.cf_list_dir_page.assert_not_called()

    def test_downstream_policy_filter_keeps_native_continuation(self):
        # Execute the actual outer web_list decorator, whose second permission
        # pass can remove the entire native page after metadata was produced.
        api = API()
        entries = [native_item(obj_name='d%05d' % i) for i in range(3)]
        api.cf_list_dir_page = Mock(return_value=wire(visible_count=3, visible_items=entries))
        source = ast.parse((ROOT / 'cloudfile_extensions/authorization/browsing.py').read_text())
        functions = [n for n in source.body if isinstance(n, ast.FunctionDef)
                     and n.name in ('web_list', 'filter_entries_batch')]
        class Resources:
            def __init__(self):
                preparation = SimpleNamespace(prepare=lambda user: None,
                    state=SimpleNamespace(username=lambda user: 'user'))
                self.resources = SimpleNamespace(preparation=lambda *args: nullcontext(preparation))
        class Authority:
            def consume(self, reference, reader): return ('rw', 'head')
            def consume_many(self, references): return [None] * len(references)
        env = dict(settings=SimpleNamespace(CLOUDFILE_OIDC_LOGIN_RESOURCES=Resources(),
                       CLOUDFILE_POLICY_CONFIG=dict(core_library=None, cloud_mode=False)),
                   nullcontext=nullcontext, wraps=__import__('functools').wraps,
                   uuid4=__import__('uuid').uuid4, posixpath=__import__('posixpath'),
                   Response=Response, ContractError=DirectoryPageError, LoginResources=Resources,
                   native_download_actor=lambda request: SimpleNamespace(user_id='id', native_username='user'),
                   OIDCSessionAuthority=lambda resources: SimpleNamespace(check=lambda request: None),
                   PolicyCore=lambda config: None, ContentReadAuthority=lambda *args, **kwargs: Authority())
        exec(compile(ast.Module(body=functions, type_ignores=[]), 'current-browsing.py', 'exec'), env)
        view = endpoint(api)
        guarded = env['web_list']('directory')(view.get.__func__)
        response = guarded(view, SimpleNamespace(GET={'start': '0', 'limit': '3'},
                            user=SimpleNamespace(username='user')), 'repo')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['dirent_list'], [])
        self.assertTrue(response.data['has_more'])
        self.assertEqual(response.data['next_start'], 3)
        self.assertFalse(response.data['scan_exhausted'])

    def test_nonpaged_api_keeps_unlimited_legacy_rpc(self):
        api = API(); api.list_dir_with_perm = Mock(return_value=[])
        response = endpoint(api).get(SimpleNamespace(GET={}, user=SimpleNamespace(username='user')), 'repo')
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('has_more', response.data)
        self.assertEqual(api.list_dir_with_perm.call_args.args[-2:], (-1, -1))

    def test_revoked_parent_is_denied_before_rpc(self):
        api = API(); api.parent_read = False; api.cf_list_dir_page = Mock()
        self.assertEqual(request(endpoint(api)).status_code, 403)
        api.cf_list_dir_page.assert_not_called()


class HubItemSchemaTest(unittest.TestCase):
    def assert_malformed(self, entries):
        api = API()
        api.cf_list_dir_page = Mock(return_value=wire(visible_count=len(entries), visible_items=entries))
        api.list_dir_with_perm = Mock(side_effect=AssertionError('No legacy fallback'))
        # Check the adapter exception and actual current endpoint's 503 mapping,
        # rather than accepting any exception as evidence of fail-closed behavior.
        with self.assertRaises(DirectoryPageError):
            read_directory_page(api, 'repo', '/', REVISION, 'user', 0, 3)
        response = request(endpoint(api))
        self.assertEqual(response.status_code, 503)
        self.assertNotIn('dirent_list', response.data)
        api.list_dir_with_perm.assert_not_called()

    def test_malformed_object_id_is_503(self):
        for value in ('bad', 'A' * 40, 'g' * 40, 'a' * 39, 'a' * 41, REVISION + '\n', None, 123):
            with self.subTest(value=value):
                self.assert_malformed([native_item(obj_id=value)])

    def test_each_missing_required_field_is_503_not_500(self):
        self.assert_malformed([{}])
        for field in native_item():
            with self.subTest(field=field):
                entry = native_item()
                del entry[field]
                self.assert_malformed([entry])

    def test_nonstring_name_is_503(self):
        for value in (None, 7, True, ['directory'], {'name': 'directory'}):
            with self.subTest(value=value):
                self.assert_malformed([native_item(obj_name=value)])

    def test_invalid_integer_fields_and_kind_are_503(self):
        for field, bits in (('mode', 32), ('version', 32), ('mtime', 64), ('size', 64), ('lock_time', 64)):
            for value in (None, True, False, '1', 1.0, [], {}, -(1 << (bits - 1)) - 1, 1 << (bits - 1)):
                with self.subTest(field=field, value=value):
                    self.assert_malformed([native_item(**{field: value})])
        # Native kind is the POSIX mode: strings, untyped modes and special file
        # kinds must not enter the endpoint's "not directory means file" branch.
        for mode in ('dir', 'file', 0, -1, stat.S_IFLNK, stat.S_IFIFO, stat.S_IFSOCK):
            with self.subTest(mode=mode):
                self.assert_malformed([native_item(mode=mode)])

    def test_nullable_strings_preserve_null_and_reject_other_types(self):
        for field in ('modifier', 'permission', 'lock_owner'):
            for value in (7, True, [], {}):
                with self.subTest(field=field, value=value):
                    self.assert_malformed([native_item(**{field: value})])
        # All nullable keys remain required. Null is valid for directories and
        # legacy version-zero files, so exercise both endpoint presentation paths.
        for mode, version in ((stat.S_IFDIR, 1), (stat.S_IFREG | 0o644, 0)):
            with self.subTest(mode=mode):
                entry = native_item(mode=mode, version=version, modifier=None,
                                    permission=None, lock_owner=None)
                api = API(); api.cf_list_dir_page = Mock(return_value=wire(visible_count=1, visible_items=[entry]))
                page = read_directory_page(api, 'repo', '/', REVISION, 'user', 0, 3)
                self.assertIsNone(page.items[0].modifier)
                self.assertIsNone(page.items[0].permission)
                self.assertIsNone(page.items[0].lock_owner)
                response = request(endpoint(api))
                self.assertEqual(response.status_code, 200)
                self.assertIsNone(response.data['dirent_list'][0]['permission'])
                self.assertEqual(response.data['dirent_list'][0]['type'],
                                 'dir' if stat.S_ISDIR(mode) else 'file')
                self.assertTrue(response.data['has_more'])
                self.assertEqual(response.data['next_start'], 3)

    def test_nonboolean_flags_are_503(self):
        for field in ('is_locked', 'is_shared'):
            for value in (None, 0, 1, 'false', [], {}):
                with self.subTest(field=field, value=value):
                    self.assert_malformed([native_item(**{field: value})])

    def test_items_require_a_list_of_objects(self):
        for value in (None, 1, 'directory', [], True):
            with self.subTest(item=value):
                self.assert_malformed([value])
        for entries in (None, {}, 'directory', 1):
            with self.subTest(entries=entries):
                api = API(); api.cf_list_dir_page = Mock(return_value=wire(visible_items=entries))
                self.assertEqual(request(endpoint(api)).status_code, 503)

    def test_mixed_page_is_rejected_before_any_item_is_exposed(self):
        with patch('cloudfile_ext.directory_page.SimpleNamespace') as presentation:
            self.assert_malformed([native_item(), native_item(obj_id='bad')])
        presentation.assert_not_called()

    def test_native_numeric_widths_and_normal_file_page(self):
        entry = native_item(mode=stat.S_IFREG | 0o644, modifier='user', size=(1 << 63) - 1,
                            mtime=-(1 << 63), lock_time=(1 << 63) - 1,
                            version=(1 << 31) - 1, is_locked=True, is_shared=True)
        api = API(); api.cf_list_dir_page = Mock(return_value=wire(visible_count=1, visible_items=[entry]))
        response = request(endpoint(api))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['dirent_list'][0]['size'], entry['size'])
        self.assertEqual(response.data['dirent_list'][0]['mtime'], entry['mtime'])
        self.assertEqual(response.data['dirent_list'][0]['modifier_email'], 'user')
        self.assertTrue(response.data['has_more'])
        self.assertEqual(response.data['next_start'], 3)


@unittest.skipUnless(os.environ.get('CF_DIR_PAGE_TEST_LIBRARY'), 'Run tests/cf-dir-page/run.sh with CF_DIR_PAGE_HUB_ROOT')
class NativeHubPagesTest(unittest.TestCase):
    def setUp(self):
        server = ROOT.parent / 'cloudfile-server'
        spec = importlib.util.spec_from_file_location('native_page_fixture', server / 'tests/cf-dir-page/test-pages.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        self.native = module.NativePageFixture(); self.native.lib.fixture_reset(10)
        self.api = API()
        # Exercise the actual Python RPC API JSON request builder as well.
        tree = ast.parse((server / 'python/seaserv/api.py').read_text())
        fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == 'cf_list_dir_page')
        env = dict(seafserv_threaded_rpc=SimpleNamespace(cf_list_dir_page=self.native.raw))
        exec(compile(ast.Module(body=[fn], type_ignores=[]), 'current-seaserv-api.py', 'exec'), env)
        self.api.cf_list_dir_page = MethodType(env['cf_list_dir_page'], self.api)
        self.view = endpoint(self.api)

    def test_shared_windows_through_native_rpc_and_hub_endpoint(self):
        cases = json.loads((ROOT.parent / 'cloudfile-docker/docs/directory-pagination-cases.json').read_text())
        for case in cases:
            with self.subTest(case=case['name']):
                self.native.lib.fixture_reset(case['total'])
                for index in case['hidden']: self.native.lib.fixture_hide(index, 1)
                seen = []
                for expected in case['pages']:
                    response = request(self.view, expected['start'], case['limit'], if_dir_id=REVISION)
                    self.assertEqual(response.status_code, 200, response.data)
                    data = response.data
                    self.assertEqual(data['dir_id'], REVISION)
                    self.assertEqual(data['has_more'], not expected['scan_exhausted'])
                    self.assertEqual(data['scan_exhausted'], expected['scan_exhausted'])
                    self.assertEqual(data['next_start'], expected['next_scan_position'])
                    self.assertEqual(data['scanned_count'], expected['scanned_count'])
                    ids = [int(item['name'][1:]) for item in data['dirent_list']]
                    self.assertEqual(ids, expected['visible']); seen.extend(ids)
                self.assertEqual(seen, [i for i in range(case.get('initial_start', 0), case['total']) if i not in case['hidden']])
                self.assertEqual(len(seen), len(set(seen)))

    def test_revision_changes_between_hub_precheck_and_native_read(self):
        self.assertEqual(request(self.view).status_code, 200)
        self.native.lib.fixture_set_revision(b'b' * 40)
        # Hub still observes R; the native RPC must catch the intervening update.
        self.assertEqual(request(self.view, 3, if_dir_id=REVISION).status_code, 409)
        self.api.revision = 'b' * 40
        self.assertEqual(request(self.view, 0).data['dir_id'], 'b' * 40)

    def test_revocation_causes_empty_continuation_without_revision_change(self):
        self.assertEqual(len(request(self.view).data['dirent_list']), 3)
        for i in (3, 4, 5): self.native.lib.fixture_hide(i, 1)
        response = request(self.view, 3, if_dir_id=REVISION)
        self.assertEqual(response.data['dirent_list'], [])
        self.assertTrue(response.data['has_more'])
        self.assertEqual(response.data['next_start'], 6)
        self.assertEqual(len(request(self.view, 6, if_dir_id=REVISION).data['dirent_list']), 3)

    def test_type_filter_does_not_change_native_continuation(self):
        response = request(self.view, t='f')
        self.assertEqual(response.data['dirent_list'], [])
        self.assertTrue(response.data['has_more'])
        self.assertEqual(response.data['next_start'], 3)

    def test_native_read_error_is_503_not_empty_terminal_page(self):
        self.native.lib.fixture_fail_read(1)
        self.assertEqual(request(self.view).status_code, 503)


if __name__ == '__main__': unittest.main()
