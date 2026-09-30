"""Real Django models/SQL and DRF view, isolated from the Seahub host bootstrap.

Run directly (SQLite), or set CF_TAG_TEST_DB_HOST/NAME for an isolated MySQL DB.
Native RPC/identity are fixtures; the legacy tag models, SQL and view are real.
"""
import json
import os
from pathlib import Path
import posixpath
import stat
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from django.conf import settings
DB = dict(ENGINE='django.db.backends.sqlite3', NAME=':memory:')
if os.environ.get('CF_TAG_TEST_DB_HOST'):
    import pymysql
    pymysql.install_as_MySQLdb()
    DB = dict(ENGINE='django.db.backends.mysql', HOST=os.environ['CF_TAG_TEST_DB_HOST'],
        NAME=os.environ['CF_TAG_TEST_DB_NAME'], USER='root', PASSWORD='', OPTIONS={'charset': 'utf8mb4'})
settings.configure(INSTALLED_APPS=['seahub.tags'], DATABASES={'default': DB}, SECRET_KEY='isolated-test',
    DEFAULT_AUTO_FIELD='django.db.models.AutoField', DEFAULT_CHARSET='utf-8', CF_ENABLE_TAGS=True,
    REST_FRAMEWORK={'UNAUTHENTICATED_USER': None, 'DEFAULT_RENDERER_CLASSES': ['rest_framework.renderers.JSONRenderer']})
api = Mock()
repo = SimpleNamespace(is_virtual=False, head_cmmt_id='a'*40)
api.get_repo.return_value = repo
api.get_dirent_by_path.return_value = SimpleNamespace(mode=stat.S_IFREG)

def module(name, **values):
    result = ModuleType(name); result.__dict__.update(values); return result
# Only bootstrap dependencies are replaced. The ORM managers and to_dict used
# for scalar equivalence below are the actual upstream legacy implementations.
sys.modules['seahub'] = module('seahub', __path__=[str(Path(__file__).resolve().parents[3] / 'seahub')])
sys.modules['seaserv'] = module('seaserv', seafile_api=api)
sys.modules['seahub.utils'] = module('seahub.utils', normalize_file_path=lambda p: '/' + p.strip('/') if p.strip('/') else '',
    normalize_dir_path=lambda p: '/' + p.strip('/') + '/' if p.strip('/') else '/')
import django
django.setup()
from django.db import connection, DatabaseError
from django.test.utils import CaptureQueriesContext
from seahub.tags.models import FileTag, FileUUIDMap, Tags
from cloudfile_ext.legacy_tags.store import tags_many
from cloudfile_ext.search.tests.test_search_access import snapshot, rule
from rest_framework.test import APIRequestFactory, force_authenticate
from rest_framework.throttling import BaseThrottle
from rest_framework.authentication import BaseAuthentication

state = snapshot()
reader = Mock(side_effect=lambda *args: state)
sys.modules['cloudfile_ext.search.access_runtime'] = module('cloudfile_ext.search.access_runtime', read_snapshot=reader)
sys.modules['seahub.api2.authentication'] = module('seahub.api2.authentication', TokenAuthentication=BaseAuthentication)
class Throttle(BaseThrottle):
    def allow_request(self, *args): return True
sys.modules['seahub.api2.throttling'] = module('seahub.api2.throttling', UserRateThrottle=Throttle)
from cloudfile_ext.legacy_tags.views import LegacyFileTagsBatch
from cloudfile_ext.hooks import check_permission

REPO = '11111111-1111-4111-8111-111111111111'
OTHER = '22222222-2222-4222-8222-222222222222'
with connection.schema_editor() as schema:
    for model in (FileUUIDMap, Tags, FileTag): schema.create_model(model)

def rpc(raw):
    request = json.loads(raw)
    return json.dumps(dict(version=1, repo_id=request['repo_id'], user=request['user'], items=[
        dict(path=p, permission='rw') for p in request['paths']]))
api.cf_check_permissions_many.side_effect = rpc
factory = APIRequestFactory()

def post(items, repo_id=REPO):
    request = factory.post('/api/v2.1/cloudfile/legacy-file-tags/batch/',
        dict(version=1, repo_id=repo_id, items=[dict(path=p, is_dir=d) for p,d in items]), format='json')
    force_authenticate(request, user=SimpleNamespace(username='alice', is_authenticated=True))
    return LegacyFileTagsBatch.as_view()(request)


def seed(paths, repo_id=REPO):
    tags = [Tags.objects.create(name='z-last'), Tags.objects.create(name='a-first')]
    for path, is_dir in paths:
        parent, name = posixpath.split(path.rstrip('/'))
        uid = FileUUIDMap.objects.create(repo_id=repo_id, parent_path=parent, filename=name, is_dir=is_dir)
        for tag in reversed(tags): FileTag.objects.create(uuid=uid, tag=tag, username='Alice')


class OrmTests(unittest.TestCase):
    def setUp(self):
        global state
        state = snapshot()
        FileTag.objects.all().delete(); Tags.objects.all().delete(); FileUUIDMap.objects.all().delete()
        api.reset_mock(); api.get_repo.side_effect = None; api.get_repo.return_value = repo
        api.get_dirent_by_path.side_effect = None
        api.get_dirent_by_path.return_value = SimpleNamespace(mode=stat.S_IFREG)
        api.cf_check_permissions_many.side_effect = rpc
        reader.side_effect = lambda *args: state

    def test_counts_scalar_equivalence_and_no_hidden_definition_n_plus_one(self):
        for count in (1, 20, 50, 100, 200):
            with self.subTest(count=count):
                self.setUp()
                items = [('/a/f'+str(i), False) for i in range(count)]
                seed(items)
                with CaptureQueriesContext(connection) as old:
                    expected = [[binding.to_dict() for binding in FileTag.objects.get_all_file_tag_by_path(REPO, '/a', 'f'+str(i), False)] for i in range(count)]
                self.assertEqual(len(old), 4*count)  # UUID + binding + two definitions per item.
                found, sql_count, rpc_count = [], 0, 0
                for start in range(0, count, 50):
                    with CaptureQueriesContext(connection) as queries:
                        result = post(items[start:start+50])
                    self.assertEqual(result.status_code, 200, result.data)
                    found.extend(i['tags'] for i in result.data['items'])
                    selects = [q['sql'] for q in queries if q['sql'].lstrip().upper().startswith('SELECT')]
                    self.assertEqual(len(selects), 2)
                    self.assertIn('tags_fileuuidmap', selects[0])
                    self.assertIn('tags_filetag', selects[1]); self.assertIn('tags_tags', selects[1])
                    self.assertIn('JOIN', selects[1]); self.assertIn('LIMIT 2001', selects[1])
                    sql_count += len(selects)
                self.assertEqual(found, expected)
                rpc_count = api.cf_check_permissions_many.call_count
                print(json.dumps(dict(items=count, old_uuid=count, old_binding=count, old_definition=2*count,
                    new_uuid=(count+49)//50, new_binding_join=(count+49)//50, new_definition_extra=0,
                    path_multi_rpc=rpc_count, new_sql=sql_count)), flush=True)

    def test_multiple_parents_root_virtual_repo_and_sparse_identity(self):
        items = [('/a/f', False), ('/b/d', True), ('/', True)]
        seed(items)
        expected = {}
        for path,directory in items:
            parent,name = posixpath.split(path.rstrip('/'))
            expected[(path,directory)] = [t.to_dict() for t in FileTag.objects.get_all_file_tag_by_path(REPO,parent,name,directory)]
        self.assertEqual(tags_many(REPO, repo, items), expected)
        before = FileUUIDMap.objects.count()
        self.assertEqual(tags_many(REPO, repo, [('/sparse', False)]), {('/sparse',False): []})
        self.assertEqual(before, FileUUIDMap.objects.count())
        virtual = SimpleNamespace(is_virtual=True, origin_repo_id=REPO, origin_path='/a', head_cmmt_id='v'*40)
        api.get_repo.return_value = virtual
        scalar = [t.to_dict() for t in FileTag.objects.get_all_file_tag_by_path(OTHER,'/','f',False)]
        self.assertEqual(tags_many(OTHER, virtual, [('/f',False)])[('/f',False)], scalar)

    def test_allow_deny_missing_provider_error_duplicate_and_multi_repo(self):
        seed([('/a',False), ('/b',False)])
        state['rules'] = [rule('/secret','invisible'), rule('/secret/open','rw'), rule('/denied','none',inherit=False)]
        state['native_rules'] = [rule('/native','invisible')]
        def lookup(r,p):
            if p == '/error': raise RuntimeError('provider')
            return None if p == '/missing' else SimpleNamespace(mode=stat.S_IFREG)
        api.get_dirent_by_path.side_effect = lookup
        response = post([(p,False) for p in ['/a','/secret/open/f','/denied','/missing','/native/f','/error','/b','/a']])
        self.assertEqual(response.status_code,200,response.data)
        self.assertEqual([i['status'] for i in response.data['items']], ['OK','DENIED','DENIED','NOT_FOUND','DENIED','FAILED','OK','OK'])
        response.data['items'][0]['tags'][0]['name']='changed'
        self.assertNotEqual(response.data['items'][-1]['tags'][0]['name'],'changed')
        self.assertEqual(post([('/a',False)], OTHER).data['items'][0]['tags'], [])

    def test_database_failure_rolls_back_and_never_publishes_empty_success(self):
        seed([('/a',False)])
        def fail(execute, sql, params, many, context):
            if 'JOIN' in sql and 'tags_filetag' in sql: raise DatabaseError('binding read failed')
            return execute(sql,params,many,context)
        with connection.execute_wrapper(fail): response = post([('/a',False)])
        self.assertEqual(response.status_code,503)
        self.assertNotIn('items',response.data)
        self.assertFalse(connection.in_atomic_block)
        self.assertEqual(FileTag.objects.count(),2)

    def test_bounded_return_rows_and_long_utf8_names(self):
        path = '/' + '中文/' * 100 + '文件'
        seed([(path,False)])
        self.assertEqual(len(tags_many(REPO,repo,[(path,False)])[(path,False)]),2)
        with patch('cloudfile_ext.legacy_tags.store.MAX_BINDINGS',1):
            self.assertEqual(post([(path,False)]).status_code,503)

    def test_final_revoke_or_head_change_discards_serialized_tags(self):
        seed([('/a',False)])
        changed=snapshot();changed['state']['active']=False
        reader.side_effect=[state,changed]
        self.assertEqual(post([('/a',False)]).status_code,503)
        reader.side_effect=lambda *args:state
        api.get_repo.side_effect=[repo,SimpleNamespace(is_virtual=False,head_cmmt_id='b'*40)]
        self.assertEqual(post([('/a',False)]).status_code,503)

    def test_native_transport_failure_and_malformed_reply_discard_batch(self):
        # Transport/provider failures must never become successful empty tags.
        seed([('/a', False)])
        for failure in (TimeoutError('timeout'), RuntimeError('native failure'), '{}'):
            api.cf_check_permissions_many.side_effect = failure if isinstance(failure, Exception) else None
            api.cf_check_permissions_many.return_value = failure
            response = post([('/a', False)])
            self.assertEqual(response.status_code, 503)
            self.assertNotIn('items', response.data)

    def test_existing_uuid_with_one_or_no_tag_keeps_scalar_contract(self):
        seed([('/a', False)])
        FileTag.objects.order_by('pk').first().delete()
        for count in (1, 0):
            expected = [t.to_dict() for t in FileTag.objects.get_all_file_tag_by_path(REPO, '/', 'a', False)]
            self.assertEqual(len(expected), count)
            self.assertEqual(post([('/a', False)]).data['items'][0]['tags'], expected)
            FileTag.objects.all().delete()

if __name__ == '__main__': unittest.main()
