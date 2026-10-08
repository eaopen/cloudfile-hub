"""Run production managers/endpoints with fake services, without a Seafile DB.

AST loading substitutes imports only, so assertions exercise actual mutation
and listing code rather than a copy of the implementation.
"""
import ast
import logging
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from cloudfile_ext.favorites.identity import pick_obj_id, should_backfill
from cloudfile_ext.favorites.lookup import LookupBudget, lookup_content_hint

ROOT = Path(__file__).resolve().parents[3]


class Q:
    def __init__(self, **values):
        self.values = values


class Query:
    def __init__(self, store, rows=None):
        self.store = store
        self.rows = list(store.rows if rows is None else rows)

    def filter(self, *conditions, **values):
        for condition in conditions:
            values.update(condition.values)
        def matches(row):
            return all(getattr(row, key[:-4]) in value if key.endswith('__in')
                       else getattr(row, key) == value for key, value in values.items())
        return Query(self.store, [row for row in self.rows if matches(row)])

    def order_by(self, field):
        self.rows.sort(key=lambda row: getattr(row, field))
        return self

    def first(self): return self.rows[0] if self.rows else None
    def exists(self): return bool(self.rows)
    def __iter__(self): return iter(self.rows)
    def __len__(self): return len(self.rows)
    def __getitem__(self, item): return self.rows[item]
    def delete(self):
        self.store.rows[:] = [row for row in self.store.rows if row not in self.rows]


class Manager:
    def __init__(self): self.rows = []
    def filter(self, *args, **kwargs): return Query(self).filter(*args, **kwargs)
    def create(self, **values):
        row = SimpleNamespace(pk=len(self.rows) + 1, save=Mock(), **values)
        self.rows.append(row)
        return row


class Response:
    def __init__(self, data, status=200): self.data, self.status_code = data, status


def load_code(path, names, env):
    nodes = [node for node in ast.parse((ROOT / path).read_text()).body
             if isinstance(node, (ast.ClassDef, ast.FunctionDef)) and node.name in names]
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec'), env)


def runtime(enabled=True):
    api = Mock()
    api.get_file_id_by_path.return_value = 'shared-content'
    api.get_dir_id_by_path.return_value = None
    api.get_dirent_by_path.return_value = None
    api.get_repo.return_value = SimpleNamespace(repo_name='library', encrypted=False, last_modified=0)
    env = dict(models=SimpleNamespace(Manager=Manager), Q=Q, logger=logging.getLogger(__name__),
               seafile_api=api, IntegrityError=ValueError, pick_obj_id=pick_obj_id,
               should_backfill=should_backfill, LookupBudget=LookupBudget,
               lookup_content_hint=lookup_content_hint,
               normalize_file_path=lambda path: path.rstrip('/') or '/',
               normalize_dir_path=lambda path: (path.rstrip('/') + '/') if path != '/' else '/')
    load_code('seahub/base/models.py', {'UserStarredFilesManager'}, env)
    manager = env['UserStarredFilesManager']()
    env['UserStarredFiles'] = SimpleNamespace(objects=manager)
    load_code('seahub/utils/star.py', {'star_file', 'unstar_file', 'is_file_starred',
                                     'resolve_obj_id', 'backfill_row_obj_id', 'locate_obj_id'}, env)
    env['is_favorites_id_enabled'] = lambda: enabled
    env.update(os=__import__('os'), APIView=object, TokenAuthentication=object,
               SessionAuthentication=object, IsAuthenticated=object, UserRateThrottle=object,
               Response=Response, is_org_context=lambda request: hasattr(request.user, 'org'),
               status=SimpleNamespace(HTTP_400_BAD_REQUEST=400, HTTP_403_FORBIDDEN=403,
                                      HTTP_404_NOT_FOUND=404, HTTP_500_INTERNAL_SERVER_ERROR=500),
               api_error=lambda code, message: Response({'error_msg': message}, code),
               timestamp_to_isoformat_timestr=str, email2nickname=lambda value: value,
               email2contact_email=lambda value: value,
               check_folder_permission=Mock(return_value='r'))
    load_code('seahub/api2/endpoints/starred_items.py', {'StarredItems'}, env)
    return env, manager, api


def row(manager, repo='repo', path='/a', user='user', org=-1, obj='shared-content'):
    return manager.create(email=user, org_id=org, repo_id=repo, path=path, is_dir=False, obj_id=obj)


def test_same_content_never_merges_paths_or_libraries():
    env, manager, _ = runtime()
    original = row(manager)
    env['star_file']('user', 'repo', '/b', False)
    env['star_file']('user', 'other', '/a', False)
    assert len(manager.rows) == 3
    assert (original.repo_id, original.path) == ('repo', '/a')
    assert {(r.repo_id, r.path) for r in manager.rows} == {('repo', '/a'), ('repo', '/b'), ('other', '/a')}


def test_same_path_remains_starred_when_content_id_changes():
    env, manager, api = runtime()
    original = row(manager)
    api.get_file_id_by_path.return_value = 'edited-content'
    env['star_file']('user', 'repo', '/a', False)
    assert len(manager.rows) == 1
    assert original.obj_id == 'edited-content'
    api.reset_mock()
    assert env['is_file_starred']('user', 'repo', '/a') is True
    assert env['is_file_starred']('user', 'repo', '/b') is False
    assert api.mock_calls == []


def test_manager_content_hint_cannot_select_or_delete_other_relationships():
    env, manager, _ = runtime()
    row(manager)
    unrelated = row(manager, path='/b')
    other_repo = row(manager, repo='other')
    other_user = row(manager, user='other-user')
    other_org = row(manager, org=7)
    assert manager.get_starred_item('user', 'repo', '/a', obj_id='changed', org_id=-1).path == '/a'
    manager.delete_starred_item('user', 'repo', '/a', obj_id='shared-content', org_id=-1)
    assert manager.rows == [unrelated, other_repo, other_user, other_org]


def test_delete_stale_or_revoked_favorite_uses_user_org_and_path_without_rpcs():
    env, manager, api = runtime()
    row(manager, obj='old-content')
    unrelated = row(manager, path='/b')
    other_user = row(manager, user='other-user')
    response = env['StarredItems']().delete(SimpleNamespace(
        GET={'repo_id': 'repo', 'path': '/a/'}, user=SimpleNamespace(username='user')))
    assert response.status_code == 200
    assert manager.rows == [unrelated, other_user]
    assert api.mock_calls == []
    assert env['check_folder_permission'].mock_calls == []


def test_delete_cannot_remove_other_users_relationship():
    env, manager, api = runtime()
    original = row(manager, user='other-user')
    response = env['StarredItems']().delete(SimpleNamespace(
        GET={'repo_id': 'repo', 'path': '/a'}, user=SimpleNamespace(username='user')))
    assert response.status_code == 404
    assert manager.rows == [original]
    assert api.mock_calls == []


def test_legacy_unstar_does_not_delete_equal_content_in_another_path_or_repo():
    env, manager, api = runtime()
    row(manager)
    other = row(manager, path='/b')
    repo = row(manager, repo='other')
    env['unstar_file']('user', 'repo', '/a/')
    assert manager.rows == [other, repo]
    assert api.mock_calls == []


def test_listing_never_backfills_reloads_or_recursively_rebinds_missing_paths():
    env, manager, api = runtime()
    old = row(manager, obj='old-content')
    legacy = row(manager, path='/legacy', obj=None)
    response = env['StarredItems']().get(SimpleNamespace(user=SimpleNamespace(username='user')))
    assert response.status_code == 200
    lost, missing = response.data['starred_item_list']
    assert lost['path'] == '/a' and lost['resolution_status'] == 'unresolved'
    assert lost['deleted'] is None
    assert missing['deleted'] is True
    assert manager.rows == [old, legacy]
    old.save.assert_not_called(); legacy.save.assert_not_called()
    api.list_dir_by_path.assert_not_called()
    api.get_file_id_by_path.assert_not_called()
    assert api.get_repo.call_count == 1


def test_directory_star_checks_target_instead_of_readable_library_root():
    env, manager, api = runtime()
    api.get_dir_id_by_path.return_value = 'directory-content'
    env['check_folder_permission'].return_value = None
    response = env['StarredItems']().post(SimpleNamespace(
        data={'repo_id': 'repo', 'path': '/secret'}, user=SimpleNamespace(username='user')))
    assert response.status_code == 403
    env['check_folder_permission'].assert_called_once()
    assert env['check_folder_permission'].call_args.args[2] == '/secret/'
    assert manager.rows == []


def test_disabled_extension_preserves_native_path_star_and_missing_list_behavior():
    env, manager, api = runtime(enabled=False)
    env['star_file']('user', 'repo', '/a', False)
    assert len(manager.rows) == 1 and manager.rows[0].obj_id is None
    env['star_file']('user', 'repo', '/a', False)
    assert len(manager.rows) == 1
    response = env['StarredItems']().get(SimpleNamespace(user=SimpleNamespace(username='user')))
    assert response.data['starred_item_list'][0]['deleted'] is True
    assert 'resolution_status' not in response.data['starred_item_list'][0]
    api.get_file_id_by_path.assert_not_called()


def test_directory_listing_stars_exact_path_not_equal_content_and_survives_edits():
    from cloudfile_ext.tests.test_directory_page import API, endpoint, request, wire, native_item
    _, manager, _ = runtime()
    repo = '11111111-1111-4111-8111-111111111111'
    row(manager, repo=repo, path='/a/', obj='a' * 40)
    api = API()
    view = endpoint(api)
    view.get.__globals__['UserStarredFiles'] = SimpleNamespace(objects=manager)
    view.get.__globals__['is_favorites_id_enabled'] = lambda: True
    for changed in (False, True):
        api.cf_list_dir_page = Mock(return_value=wire(scanned_count=2, scan_exhausted=True,
            next_scan_position=None, visible_count=2,
            visible_items=[native_item(obj_name='a', obj_id=('b' if changed else 'a') * 40),
                           native_item(obj_name='b', obj_id='a' * 40)]))
        response = request(view)
        assert response.status_code == 200
        entries = response.data['dirent_list']
        assert entries[0]['name'] == 'a' and entries[0]['starred'] is True
        assert entries[1]['name'] == 'b' and entries[1]['starred'] is False
