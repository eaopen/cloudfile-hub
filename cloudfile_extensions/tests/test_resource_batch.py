"""Real batch/authorization/SQL-building paths with counted I/O fixtures.

The fake cursor validates statement shapes, not SQL engine or native C policy.
Integration tests cover collection SQL separately; evaluation is a counted mock.
"""
from collections import Counter
from contextlib import contextmanager
from copy import deepcopy
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch
from uuid import UUID

from cloudfile_extensions.authorization.qualification import NativeLibraryQualification
from cloudfile_extensions.authorization.read import ContentReadAuthority
from cloudfile_extensions.authorization.rules import ACLRules
from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.directory.preparation import SubjectPreparation
from cloudfile_extensions.resources.service import ResourceService
from cloudfile_extensions.resources.store import ResourceStore, ResourceEvidence
from cloudfile_extensions.tags.read import bound_tags_many, FIELDS


def uid(number):
    return str(UUID(int=number))


class CountedConnection:
    """Fail on unexpected SQL or transaction escape; never emulate permissions."""
    def __init__(self):
        self.counts = Counter()
        self.events = []
        self.active = False
        self.rows = {}
        self.bindings = []
        self.definitions = {}
        self.queries = []
        self.status = 0

    def get_autocommit(self):
        return True

    def begin(self):
        assert not self.active
        self.active = True
        self.events.append('begin')

    def commit(self):
        assert self.active
        self.active = False
        self.events.append('commit')
        self.counts['commit'] += 1

    def rollback(self):
        self.active = False
        self.events.append('rollback')
        self.counts['rollback'] += 1

    @contextmanager
    def cursor(self):
        yield CountedCursor(self)


class CountedCursor:
    def __init__(self, connection):
        self.connection = connection

    def execute(self, sql, args=()):
        c = self.connection
        assert c.active, 'SQL escaped authorization transaction'
        c.queries.append((sql, args))
        c.events.append('sql')
        self.rows = ()
        if 'cf_resource' in sql or ('information_schema.statistics' in sql and "'cf_resource'" in sql):
            c.counts['resource_sql'] += 1
        if ('cf_tag' in sql or any(value in ('cf_tag', 'cf_tag_binding') for value in args)):
            c.counts['tag_sql'] += 1
        if 'LIMIT 0' in sql:
            return
        if sql.startswith('SELECT ENGINE'):
            self.rows = (('InnoDB',),)
        elif sql.startswith('SELECT column_name,non_unique'):
            self.rows = ((('uid', 0, None),) if args == ('PRIMARY',) else
                (('repo_id', 1, None), ('path_hash', 1, None), ('kind', 1, None)))
        elif sql.startswith('SELECT GROUP_CONCAT'):
            self.rows = (('resource_uid,tag_id' if args[0] == 'cf_tag_binding' else 'tag_id',),)
        elif sql.startswith('SELECT email,is_active,is_staff'):
            self.rows = (('native-user', 1, 0),)
        elif sql.startswith('SELECT user,login_id'):
            self.rows = (('native-user', 'employee'),)
        elif sql.startswith('SELECT repo_id FROM Repo '):
            self.rows = ((args[0],),)
        elif sql.startswith('SELECT status FROM RepoInfo'):
            self.rows = ((c.status,),)
        elif sql.startswith('SELECT repo_id FROM VirtualRepo'):
            pass
        elif sql.startswith('SELECT owner_id FROM RepoOwner'):
            self.rows = (('native-user',),)
        elif sql.startswith('SELECT @@transaction_isolation'):
            c.counts['qualification_sql'] += 1
            self.rows = (('REPEATABLE-READ',),)
        elif 'FROM cf_dir_acl WHERE' in sql:
            c.counts['candidates_query'] += 1
        elif sql.startswith('SELECT kind,uid,path'):
            assert len(args) <= 151 and ' LIMIT ' in sql and 'FOR UPDATE' in sql
            keys = [(args[0], args[index + 1], args[index + 2]) for index in range(1, len(args), 3)]
            self.rows = tuple((key[1], *c.rows[key]) for key in reversed(keys) if key in c.rows)
        elif sql.startswith('SELECT uid,path'):
            key = (args[0], args[2], args[3])
            self.rows = (c.rows[key],) if key in c.rows else ()
        elif sql.startswith('SELECT resource_uid,tag_id'):
            assert len(args) <= 50 and ' LIMIT ' in sql
            self.rows = tuple(row for row in c.bindings if row[0] in args)
        elif sql.startswith('SELECT tag_id FROM cf_tag_binding'):
            self.rows = tuple((tag,) for resource, tag in c.bindings if resource == args[0])
        elif sql.startswith('SELECT ' + FIELDS):
            assert len(args) <= 6400
            self.rows = tuple(c.definitions[tag] for tag in reversed(args) if tag in c.definitions)
        else:
            raise AssertionError('Unexpected SQL: ' + sql)

    def fetchall(self):
        return self.rows


class ResourceBatchTest(TestCase):
    def setUp(self):
        self.connection = CountedConnection()
        self.context = dict(context_epoch='epoch', subject=dict(userId='employee'))
        self.preparation = object.__new__(SubjectPreparation)
        self.preparation.actor = 'employee'
        self.preparation._read_epoch = None
        self.preparation.contexts = SimpleNamespace(allowlist=(),
            current=Mock(side_effect=lambda actor: self.context))
        # Match SubjectContexts.get's already-ready path, including its current
        # check, so reported counts include the initial request preparation.
        self.preparation.contexts.get = Mock(side_effect=lambda actor, **kwargs:
            self.preparation.contexts.current(actor))
        self.state = SimpleNamespace(connection=self.connection, provider='directory',
            username=Mock(return_value='native-user'), accounts='accounts', profiles='profiles',
            native_schema='native', identity_schema='identity', barrier_active=Mock(return_value=False),
            jobs=SimpleNamespace(active_barrier=Mock(return_value=False)))
        self.authority = object.__new__(ContentReadAuthority)
        self.authority.actor = 'employee'
        self.authority.state = self.state
        self.authority.preparation = self.preparation
        self.authority.native_qualification = NativeLibraryQualification(native_schema='native', cloud_mode=False)
        self.authority.native_qualification.read = Mock(wraps=self.authority.native_qualification.read)
        self.authority.rules = object.__new__(ACLRules)
        self.authority.rules.connection = self.connection
        # Real candidate collection/partitioning; schema metadata has separate SQL integration coverage.
        self.authority.rules._require_storage = Mock()
        self.authority.rules.candidates_many = Mock(wraps=self.authority.rules.candidates_many)
        self.authority.rules.candidates = Mock(wraps=self.authority.rules.candidates)
        self.denied = set()
        self.missing = set()
        self.authority.core = SimpleNamespace(evaluate=Mock(side_effect=self.evaluate))
        self.service = object.__new__(ResourceService)
        self.service.read_authority = self.authority
        self.service.reader = Mock(side_effect=self.lifecycle)
        self.service.store = ResourceStore(self.connection, inspector=Mock(), write_guard=Mock(),
            secret=b'batch-test-secret-at-least-32-bytes', mutation_hook=Mock())
        self.held = Counter()
        for target in ('cloudfile_extensions.jobs.authority.scope_locks',
                       'cloudfile_extensions.authorization.read.scope_locks'):
            patcher = patch(target, side_effect=self.guards)
            patcher.start()
            self.addCleanup(patcher.stop)

    @contextmanager
    def guards(self, connection, scopes):
        assert connection is self.connection and 1 <= len(scopes) <= 16
        keys = [(scope['type'], scope['external_id']) for scope in scopes]
        self.held.update(keys)
        try:
            yield
        finally:
            self.held.subtract(keys)

    def evaluate(self, ref, **kwargs):
        assert self.connection.active and self.held['repo', ref['repo_id']] > 0
        return dict(visible=ref['path'] not in self.denied, read=ref['path'] not in self.denied,
                    write=ref['path'] not in self.denied and not kwargs['hard_readonly'])

    def lifecycle(self, cursor, ref):
        assert cursor.connection is self.connection and self.connection.active
        assert ref['path'] not in self.denied
        self.connection.events.append('lifecycle')
        if ref['path'] in self.missing:
            raise ContractError('NOT_FOUND', 'missing', 404)
        return ResourceEvidence('birth')

    def refs(self, count, *, repo=None, annotated=True, tags=True):
        repo = repo or uid(1)
        result = [dict(repo_id=repo, path='/item-' + str(index), kind='file') for index in range(count)]
        for index, ref in enumerate(result):
            resource_uid = uid(1000 + index)
            if annotated:
                self.connection.rows[repo, 'file', ref['path']] = (resource_uid, ref['path'], 'birth', 1, 'CAD', None)
            if tags:
                tag = uid(2000)
                self.connection.bindings.append((resource_uid, tag))
                self.connection.definitions[tag] = (tag, 'system', 'source', 'category', 'drawing',
                    'drawing', None, None, 1, None, uid(3000))
        return result

    def read(self, refs):
        return self.service.batch_resolve(dict(references=refs))['items']

    def test_structure_1_20_21_100(self):
        for count in (1, 20, 21, 100):
            with self.subTest(count=count):
                self.setUp()
                refs = self.refs(count)
                with patch.object(self.service, 'resolve', side_effect=AssertionError('per-item resolve')):
                    result = self.read(refs)
                groups = (count + 19) // 20
                self.assertEqual(len(result), count)
                self.assertTrue(all(item['status'] == 200 for item in result))
                self.assertEqual(self.authority.core.evaluate.call_count, count)
                self.assertEqual(self.authority.native_qualification.read.call_count, groups)
                self.assertEqual(self.state.username.call_count, groups)
                self.assertEqual(self.authority.rules.candidates_many.call_count, groups)
                self.authority.rules.candidates.assert_not_called()
                self.assertEqual(self.connection.counts['candidates_query'], groups)
                self.assertEqual(self.connection.counts['resource_sql'], 5 * groups)
                self.assertEqual(self.connection.counts['tag_sql'], 8 * groups)
                self.assertEqual(self.preparation.contexts.current.call_count, 2 * groups + 6)
                self.assertEqual(self.connection.counts['commit'], groups)
                self.assertEqual(self.connection.counts['rollback'], groups)
                self.assertFalse(self.connection.active)

    def test_previous_single_read_structure_has_linear_repeated_loading(self):
        # Reproduce the former batch loop with today's unchanged single read:
        # this is a baseline counter, not a second production batch pathway.
        for count in (1, 20, 21, 100):
            with self.subTest(count=count):
                self.setUp()
                refs = self.refs(count)
                self.preparation.prepare('employee')
                self.preparation.contexts.current('employee')
                with self.preparation.no_refresh_scope():
                    for ref in refs:
                        self.service.resolve(dict(reference=ref))
                        self.preparation.contexts.current('employee')
                self.assertEqual(self.preparation.contexts.current.call_count, 4 * count + 4)
                self.assertEqual(self.authority.native_qualification.read.call_count, count)
                self.assertEqual(self.connection.counts['candidates_query'], count)
                self.assertEqual(self.authority.core.evaluate.call_count, count)
                self.assertEqual(self.connection.counts['resource_sql'], 5 * count)
                self.assertEqual(self.connection.counts['tag_sql'], 8 * count)

    def test_normalizes_before_preparation_and_bounds_count(self):
        refs = self.refs(2)
        for values in ([], refs * 51, [refs[0], {**refs[1], 'path': '/../bad'}]):
            with self.assertRaises(ContractError):
                self.read(values)
        self.preparation.contexts.get.assert_not_called()

    def test_multi_repo_order_duplicates_and_more_than_16_scopes(self):
        # No sparse rows avoids accidentally aliasing fixture UIDs between repos.
        refs = [dict(repo_id=uid(index + 1), path='/folder/', kind='dir') for index in range(20)]
        requested = list(reversed(refs)) + [refs[2], {**refs[2], 'path': '/folder'}]
        result = self.read(requested)
        self.assertEqual([item['reference']['repo_id'] for item in result], [ref['repo_id'] for ref in requested])
        self.assertEqual(result[-2], result[-1])
        self.assertEqual(self.authority.core.evaluate.call_count, 20)
        self.assertEqual(self.authority.native_qualification.read.call_count, 20)
        self.assertTrue(all(value == 0 for value in self.held.values()))

    def test_duplicate_snapshot_mutations_are_isolated_without_repeating_reads(self):
        refs = self.refs(2)
        original_snapshot = self.service.store._snapshot
        def snapshot_with_metadata(*args):
            value = original_snapshot(*args)
            # Fixture-only nested JSON guards against a shallow copy if the
            # DTO gains metadata fields; no production response fields change.
            value['metadata'] = {'entries': [{'labels': ['original']}]}
            return value
        requested = [refs[0], refs[1], refs[0]]
        with patch.object(self.service.store, '_snapshot', side_effect=snapshot_with_metadata):
            items = self.read(requested)
        before = deepcopy(items)
        self.assertEqual([item['reference'] for item in items], requested)
        self.assertEqual(items[0], items[2])
        first = items[0]['snapshot']
        repeated = items[2]['snapshot']
        self.assertIsNot(first, repeated)
        self.assertIsNot(first['metadata']['entries'], repeated['metadata']['entries'])
        self.assertIsNot(first['tags'][0], repeated['tags'][0])
        first['description'] = 'first slot only'
        first['metadata']['entries'][0]['labels'].append('changed')
        first['tags'][0]['label'] = 'first resource only'
        first['tags'].append({'tag_id': uid(9999)})
        first['access']['write'] = False
        first['resource']['path'] = '/changed-in-first-dto'
        self.assertEqual(items[1:], before[1:])
        self.assertEqual(first['uid'], before[0]['snapshot']['uid'])
        self.assertEqual(first['revision'], before[0]['snapshot']['revision'])
        self.assertEqual(self.authority.core.evaluate.call_count, 2)
        self.assertEqual(self.service.reader.call_count, 2)
        self.assertEqual(self.authority.rules.candidates_many.call_count, 1)
        self.assertEqual(self.connection.counts['resource_sql'], 5)
        self.assertEqual(self.connection.counts['tag_sql'], 8)

    def test_bound_tags_many_isolates_resource_dtos_and_nested_values(self):
        self.refs(2)
        user_tag = uid(2001)
        self.connection.definitions[user_tag] = (user_tag, 'user', 'cloudfile', 'user:' + uid(1), user_tag,
            'Alpha', 'Alpha', None, 1, uid(1), uid(3001))
        self.connection.bindings.extend([(uid(1000), user_tag), (uid(1001), user_tag)])
        from cloudfile_extensions.tags.definitions import decode
        decoded = []
        def definition_with_metadata(row):
            value = decode(row)
            # Fixture-only nesting proves isolation beyond today's scalar tag
            # fields, and verifies returned DTO mutations cannot affect inputs.
            value['metadata'] = {'labels': [{'value': 'original'}]}
            decoded.append(value)
            return value
        self.connection.begin()
        try:
            with self.connection.cursor() as cursor, patch('cloudfile_extensions.tags.read.decode',
                    side_effect=definition_with_metadata):
                result = bound_tags_many(cursor, resources={uid(1000): uid(1), uid(1001): uid(1)})
        finally:
            self.connection.rollback()
        before = deepcopy(result)
        inputs_before = deepcopy(decoded)
        first, second = result[uid(1000)], result[uid(1001)]
        self.assertEqual(first, second)
        self.assertEqual([tag['kind'] for tag in first], ['system', 'user'])
        self.assertEqual([tag['tag_id'] for tag in first], [uid(2000), user_tag])
        self.assertIsNot(first[0], second[0])
        self.assertIsNot(first[0]['metadata']['labels'], second[0]['metadata']['labels'])
        first[0]['label'] = 'first resource only'
        first[0]['metadata']['labels'][0]['value'] = 'changed'
        first[0]['metadata']['labels'].append({'value': 'new'})
        first.append({'tag_id': uid(9999)})
        self.assertEqual(second, before[uid(1001)])
        self.assertEqual(decoded, inputs_before)
        self.assertEqual(len(decoded), 2)
        self.assertEqual(self.connection.counts['tag_sql'], 8)

    def test_partial_and_all_deny_do_not_read_denied_metadata(self):
        refs = self.refs(3)
        self.denied = {'/item-0', '/item-2'}
        result = self.read(refs)
        self.assertEqual([item['status'] for item in result], [404, 200, 404])
        self.assertEqual(set(result[0]), {'reference', 'status'})
        self.assertEqual(self.service.reader.call_count, 1)
        selected = next(args for sql, args in self.connection.queries if sql.startswith('SELECT kind,uid'))
        self.assertEqual(selected[-1], '/item-1')
        self.assertEqual(len(selected), 4)
        self.connection.counts.clear()
        self.denied.add('/item-1')
        result = self.read(refs)
        self.assertEqual([item['status'] for item in result], [404] * 3)
        self.assertEqual(self.connection.counts['resource_sql'], 0)
        self.assertEqual(self.connection.counts['tag_sql'], 0)
        self.assertEqual(self.service.reader.call_count, 1)

    def test_missing_sparse_no_tags_multi_tags_and_single_parity(self):
        refs = self.refs(4, tags=False)
        self.missing.add('/item-0')
        del self.connection.rows[uid(1), 'file', '/item-1']
        self.refs(1)  # One shared system tag, bound to item-0 (which is missing).
        tag = uid(2001)
        self.connection.definitions[tag] = (tag, 'user', 'cloudfile', 'user:' + uid(1), tag,
            'Alpha', 'Alpha', None, 0, uid(1), uid(3001))
        self.connection.bindings.extend([(uid(1003), tag), (uid(1003), uid(2000))])
        result = self.read(refs)
        self.assertEqual([item['status'] for item in result], [404, 200, 200, 200])
        self.assertIsNone(result[1]['snapshot']['uid'])
        self.assertEqual(result[1]['snapshot']['tags'], [])
        self.assertEqual(result[2]['snapshot']['tags'], [])
        self.assertEqual([tag['kind'] for tag in result[3]['snapshot']['tags']], ['system', 'user'])
        for index in (1, 2, 3):
            self.assertEqual(self.service.resolve(dict(reference=refs[index])), result[index]['snapshot'])
        with self.assertRaises(ContractError) as caught:
            self.service.resolve(dict(reference=refs[0]))
        self.assertEqual(caught.exception.status, 404)
        self.assertTrue(all(sql.startswith('SELECT') for sql, args in self.connection.queries))

    def test_long_utf8_path_and_over_budget_keep_error_contract(self):
        ref = dict(repo_id=uid(1), path='/' + '路径' * 680, kind='file')
        result = self.read([ref, ref])
        self.assertEqual([item['reference'] for item in result], [ref, ref])
        self.assertEqual(self.authority.core.evaluate.call_count, 1)
        for action in (self.read, lambda refs: self.service.resolve(dict(reference=refs[0]))):
            with self.assertRaises(ContractError) as caught:
                action([{**ref, 'path': '/' + '路' * 1400}])
            self.assertEqual(caught.exception.status, 400)

    def test_reader_failure_rolls_back_and_later_group_never_publishes_partial(self):
        refs = self.refs(21)
        original = self.service.reader.side_effect
        def failing(cursor, ref):
            if ref['path'] == '/item-20':
                raise RuntimeError('native head/session unavailable')
            return original(cursor, ref)
        self.service.reader.side_effect = failing
        with self.assertRaises(ContractError) as caught:
            self.read(refs)
        self.assertEqual(caught.exception.code, 'POLICY_UNAVAILABLE')
        self.assertEqual(self.connection.counts['commit'], 1)
        self.assertEqual(self.connection.counts['rollback'], 2)
        self.assertFalse(self.connection.active)
        self.assertIsNone(self.authority.current_subject)
        self.assertIsNone(self.preparation._read_epoch)

    def test_epoch_expiry_and_barrier_change_after_reader_fail_before_commit(self):
        for failure in ('epoch', 'expired', 'barrier'):
            with self.subTest(failure=failure):
                self.setUp()
                original = self.lifecycle
                def change(cursor, ref):
                    value = original(cursor, ref)
                    if failure == 'epoch':
                        self.context = {**self.context, 'context_epoch': 'changed'}
                    elif failure == 'expired':
                        self.context = None
                    else:
                        self.state.jobs.active_barrier.return_value = True
                    return value
                self.service.reader.side_effect = change
                with self.assertRaises(ContractError) as caught:
                    self.read(self.refs(1))
                self.assertEqual(caught.exception.code, 'SUBJECT_UNAVAILABLE')
                self.assertEqual(self.connection.counts['commit'], 0)
                self.assertEqual(self.connection.counts['rollback'], 1)

    def test_deadline_and_final_response_epoch_check_discard_results(self):
        refs = self.refs(1)
        # A long reader must not publish even though it already loaded data.
        with patch('time.monotonic', return_value=0) as clock:
            def late(cursor, ref):
                clock.return_value = 21
                return self.lifecycle(cursor, ref)
            self.service.reader.side_effect = late
            with self.assertRaises(ContractError) as caught:
                self.read(refs)
            self.assertEqual(caught.exception.code, 'RESOURCE_UNAVAILABLE')
        self.assertEqual(self.connection.counts['commit'], 0)
        self.service.reader.side_effect = self.lifecycle
        original = self.service.store.resolve_many_authorized
        def changed_after_commit(*args, **kwargs):
            results = original(*args, **kwargs)
            self.context = {**self.context, 'context_epoch': 'changed'}
            return results
        with patch.object(self.service.store, 'resolve_many_authorized', side_effect=changed_after_commit):
            with self.assertRaises(ContractError) as caught:
                self.read(refs)
            self.assertEqual(caught.exception.code, 'SUBJECT_UNAVAILABLE')
        self.assertEqual(self.connection.counts['commit'], 1)
        self.assertIsNone(self.preparation._read_epoch)

    def test_reader_sees_only_authorized_objects_and_cardinality_is_checked(self):
        refs = self.refs(3)
        self.denied.add('/item-0')
        def read(cursor, targets, accesses):
            self.assertTrue(self.connection.active)
            self.assertEqual(targets, refs[1:])
            self.assertEqual(accesses, [dict(read=True, write=True)] * 2)
            return ['second', 'third']
        self.assertEqual(self.authority.consume_many(refs, reader=read), [None, 'second', 'third'])
        self.assertEqual(self.authority.consume_many(refs), [None, 'rw', 'rw'])
        for reader in (lambda *args: [], lambda *args: 'invalid'):
            with self.assertRaises(ContractError):
                self.authority.consume_many(refs, reader=reader)
        self.authority.rules.candidates_many.return_value = []
        self.authority.rules.candidates_many.side_effect = None
        with self.assertRaises(ContractError):
            self.authority.consume_many(refs)

    def test_readonly_and_unqualified_library_cannot_gain_write_or_read(self):
        refs = self.refs(2)
        self.connection.status = 1
        result = self.read(refs)
        self.assertTrue(all(item['snapshot']['access'] == dict(read=True, write=False) for item in result))
        self.connection.counts.clear()
        self.connection.status = 2
        self.assertTrue(all(item['status'] == 404 for item in self.read(refs)))
        self.assertEqual(self.connection.counts['resource_sql'], 0)

    def test_tag_orphan_foreign_scope_duplicate_and_overflow_fail_closed(self):
        refs = self.refs(1)
        self.connection.definitions.clear()
        with self.assertRaises(ContractError) as caught:
            self.read(refs)
        self.assertEqual(caught.exception.code, 'TAGS_UNAVAILABLE')
        self.refs(1)
        self.connection.bindings = [(uid(1000), uid(2000))] * 2
        with self.assertRaises(ContractError):
            self.read(refs)
        self.connection.bindings = [(uid(1000), uid(4000 + index)) for index in range(129)]
        with self.assertRaises(ContractError):
            self.read(refs)
        self.connection.bindings = [(uid(1000), uid(2000))]
        row = self.connection.definitions[uid(2000)]
        self.connection.definitions[uid(2000)] = (*row[:9], uid(99), row[10])
        with self.assertRaises(ContractError):
            self.read(refs)
        self.assertEqual(self.connection.counts['commit'], 0)

    def test_lifecycle_mismatch_and_resource_query_failure_abort(self):
        refs = self.refs(1)
        row = self.connection.rows[uid(1), 'file', '/item-0']
        self.connection.rows[uid(1), 'file', '/item-0'] = (*row[:2], 'reborn', *row[3:])
        with self.assertRaises(ContractError) as caught:
            self.read(refs)
        self.assertEqual(caught.exception.code, 'PATH_STATE_PENDING')
        self.assertEqual(self.connection.counts['tag_sql'], 0)
        with patch.object(self.service.store, 'resource_rows_many', side_effect=RuntimeError('database down')):
            with self.assertRaises(ContractError):
                self.read(refs)
        self.assertEqual(self.connection.counts['commit'], 0)
