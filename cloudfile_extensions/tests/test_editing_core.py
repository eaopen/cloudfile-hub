"""Single-file workflow in isolated SQL; native publication is a test double."""
from contextlib import contextmanager
import hashlib
from uuid import uuid4

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.editing.store import EditingStore
from cloudfile_extensions.tests.editing_sql import WORKSPACE, checkout_queries, native_intent_query, native_publication_updates
from cloudfile_extensions.schema.runner import SchemaRunner
from cloudfile_extensions.tests.test_schema import DatabaseTestCase


class EditingCoreTest(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        SchemaRunner(self.connection).apply()
        self.store = EditingStore()
        self.target = dict(uid='11111111-1111-4111-8111-111111111111',
                           repo='22222222-2222-4222-8222-222222222222', lifecycle='fixture')
        self.path = '/folder/a.docx'
        self.identity = dict(actor='employee', holder='device', token='a' * 64)
        with self.connection.cursor() as sql:
            sql.execute('CREATE TABLE fixture_content(repo CHAR(36) PRIMARY KEY,file_id CHAR(40)) ENGINE=InnoDB')
            sql.execute('INSERT INTO fixture_content VALUES(%s,%s)', (self.target['repo'], 'b' * 40))
            sql.execute("INSERT INTO cf_resource(uid,repo_id,kind,path,path_hash,lifecycle_ref,revision,state,updated_at) VALUES(%s,%s,'file',%s,%s,%s,1,'active',UTC_TIMESTAMP(6))",
                        (self.target['uid'], self.target['repo'], self.path,
                         hashlib.sha256(self.path.encode()).hexdigest(), self.target['lifecycle']))

    @contextmanager
    def transaction(self):
        self.connection.begin()
        try:
            with self.connection.cursor() as sql:
                yield sql
            self.connection.commit()
        except BaseException:
            self.connection.rollback()
            raise

    def acquire(self, sql, mode='checkout', **kwargs):
        return self.store.acquire(sql, **self.target, **self.identity,
                                  mode=mode, source='local-agent', base_file_id='b' * 40, native_user='employee', **kwargs)

    def proof(self, guard):
        return dict(self.identity, guard_id=guard['guard_id'], generation=int(guard['generation']),
                    credential_epoch=int(guard['credential_epoch']))

    def prepare(self, sql, proof, action='commit', base='b', staged='c'):
        return self.store.prepare(sql, **self.target, **proof, intent_id=str(uuid4()),
                                  expected_file_id=base * 40, staged_file_id=staged * 40,
                                  content_digest='e' * 64, action=action, snapshot=dict(id=str(uuid4()),size=0,source='fixture-workcopy'))

    def native_publish(self, sql, proof, intent_id, *, after_content=None):
        """Exercise the production C predicate and native transaction SQL."""
        intent = self.store.intent(sql, uid=self.target['uid'], intent_id=intent_id)
        if intent['state'] == 'published':
            return intent
        row = self.store.load(sql, **self.target)
        self.store.proof(row, **proof)
        sql.execute('SELECT file_id FROM fixture_content WHERE repo=%s FOR UPDATE',
                    (self.target['repo'],))
        old_file = sql.fetchone()[0]
        new_file = intent['staged_file_id'] or 'c' * 40
        query = native_intent_query(WORKSPACE / 'cloudfile-server/server/cloudfile-policy.c')
        params = (self.target['repo'], self.target['uid'], hashlib.sha256(self.path.encode()).hexdigest(),
            self.path, proof['guard_id'], str(proof['generation']),
            str(proof['credential_epoch']), proof['actor'], 'employee', proof['holder'],
            hashlib.sha256(proof['token'].encode()).hexdigest(), intent_id,
            old_file, new_file, intent['content_digest'], 0)
        sql.execute(query.replace('?', '%s'), params)
        if sql.fetchall() != ((intent['action'],),):
            raise ContractError('RESOURCE_VERSION_CONFLICT', 'Native publication fenced', 409)
        if new_file != old_file:
            sql.execute('UPDATE fixture_content SET file_id=%s WHERE repo=%s AND file_id=%s',
                        (new_file, self.target['repo'], old_file))
            if sql.rowcount != 1:
                raise ContractError('RESOURCE_VERSION_CONFLICT', 'Native content changed', 409)
        if after_content:
            after_content(sql)
        sql.execute(query.replace('?', '%s'), params)
        if sql.fetchall() != ((intent['action'],),):
            raise ContractError('EDIT_CONFLICT', 'Checkout expired during publication', 409)
        receipt_update, release_update, commit_update = native_publication_updates(
            WORKSPACE / 'cloudfile-server/server/cloudfile-policy.c')
        sql.execute(receipt_update.replace('?', '%s'),
                    (new_file, new_file, 'd' * 40, intent_id))
        if intent['action'] in ('checkin', 'checkin-unchanged'):
            sql.execute(release_update.replace('?', '%s'), (proof['guard_id'], intent_id))
        else:
            sql.execute(commit_update.replace('?', '%s'),
                        (new_file, proof['guard_id'], intent_id))
        return self.store.intent(sql, uid=self.target['uid'], intent_id=intent_id)

    def test_checkout_commit_query_then_final_checkin(self):
        with self.transaction() as sql:
            guard = self.acquire(sql)
            proof = self.proof(guard)
            intent = self.prepare(sql, proof)
        with self.transaction() as sql:
            result = self.native_publish(sql, proof, intent['intent_id'])
            self.assertEqual(result['state'], 'published')
            current = self.store.load(sql, **self.target)
            self.assertEqual(current['base_file_id'], 'c' * 40)
            self.assertIsNotNone(current['guard_id'])
        # Lost HTTP response: durable receipt survives transaction/connection scope.
        with self.transaction() as sql:
            self.assertEqual(self.store.intent(sql, uid=self.target['uid'], intent_id=intent['intent_id']), result)
            self.assertEqual(self.native_publish(sql, proof, intent['intent_id']), result)
            second = self.prepare(sql, proof, base='c', staged='f')
            self.native_publish(sql, proof, second['intent_id'])
            self.assertEqual(self.store.load(sql, **self.target)['base_file_id'], 'f' * 40)
            last = self.store.prepare(sql, **self.target, **proof,
                intent_id=str(uuid4()), expected_file_id='f' * 40,
                staged_file_id='f' * 40,
                content_digest=hashlib.sha256(b'').hexdigest(), action='checkin-unchanged')
            self.native_publish(sql, proof, last['intent_id'])
            self.assertIsNone(self.store.load(sql, **self.target)['guard_id'])
            self.assertEqual(self.store.intent(sql, uid=self.target['uid'], intent_id=last['intent_id'])['state'], 'published')

    def test_checkout_blocks_owner_and_other_plain_writes_while_manual_lock_allows_owner(self):
        early = checkout_queries(WORKSPACE / 'cloudfile-server/common/cf-lock.c')[0]
        final = checkout_queries(WORKSPACE / 'cloudfile-server/server/cloudfile-policy.c')[0]
        queries = (early, final)
        params = (self.target['repo'], hashlib.sha256(self.path.encode()).hexdigest(), self.path)
        with self.transaction() as sql:
            guard = self.acquire(sql)
            for query in queries:
                for user in ('employee', 'another-user'):
                    sql.execute(query.replace('?', '%s'), (*params, user))
                    self.assertEqual(sql.fetchall(), ((self.target['uid'],),))
            self.store.release(sql, **self.target, actor='employee',
                guard_id=guard['guard_id'], generation=int(guard['generation']),
                proof=dict(holder='device', token='a' * 64, credential_epoch=1))
            self.store.acquire(sql, **self.target, **self.identity, mode='file-lock',
                source='web', base_file_id='b' * 40, native_user='native-employee')
            for query in queries:
                sql.execute(query.replace('?', '%s'), (*params, 'native-employee'))
                self.assertEqual(sql.fetchall(), ())
                sql.execute(query.replace('?', '%s'), (*params, 'another-user'))
                self.assertEqual(sql.fetchall(), ((self.target['uid'],),))

    def test_pending_intent_blocks_abandon_resume_and_competing_save(self):
        with self.transaction() as sql:
            guard = self.acquire(sql)
            proof = self.proof(guard)
            intent = self.prepare(sql, proof)
            with self.assertRaises(ContractError):
                self.store.release(sql, **self.target, actor='employee', guard_id=guard['guard_id'], generation=int(guard['generation']),
                                   proof=dict(holder='device', token='a'*64, credential_epoch=1))
            with self.assertRaises(ContractError):
                self.prepare(sql, proof)
            with self.assertRaises(ContractError):
                self.store.resume(sql, **self.target, actor='employee', guard_id=guard['guard_id'], generation=1, credential_epoch=1,
                                  holder='other', token='f'*64, expected_file_id='b'*40)
            self.store.cancel_prepared(sql, **self.target, **proof, intent_id=intent['intent_id'])
            self.store.release(sql, **self.target, actor='employee', guard_id=guard['guard_id'], generation=1,
                               proof=dict(holder='device', token='a'*64, credential_epoch=1))

    def test_native_owner_binding_is_distinct_from_business_actor_and_fences_remapping(self):
        with self.transaction() as sql:
            self.store.acquire(sql, **self.target, **self.identity, mode='checkout',
                source='web', base_file_id='b'*40, native_user='native-account@example.test')
            row = self.store.load(sql, **self.target)
            self.assertEqual(row['owner'], 'employee')
            self.assertEqual(row['owner_native_user'], 'native-account@example.test')
            self.store.native_owner(row, 'native-account@example.test')
            for changed in ('employee', 'oidc-subject', 'another-native@example.test'):
                with self.subTest(changed=changed), self.assertRaises(ContractError) as caught:
                    self.store.native_owner(row, changed)
                self.assertEqual(caught.exception.status, 403)

    def test_resume_rotates_credentials_without_releasing_reservation(self):
        with self.transaction() as sql:
            guard = self.acquire(sql)
            sql.execute('UPDATE cf_edit_guard SET lease_until=TIMESTAMPADD(SECOND,-1,UTC_TIMESTAMP(6))')
            self.assertEqual(self.store.public(self.store.load(sql, **self.target))['state'], 'suspended')
            with self.assertRaises(ContractError):
                self.acquire(sql)
            renewed = self.store.resume(sql, **self.target, actor='employee', guard_id=guard['guard_id'], generation=1, credential_epoch=1,
                                        holder='new-device', token='f'*64, expected_file_id='b'*40)
            self.assertEqual(renewed['credential_epoch'], '2')
            self.assertEqual(renewed['generation'], '1')
            with self.assertRaises(ContractError):
                self.store.renew(sql, **self.target, **self.proof(guard))

    def test_manual_lock_conversion_uses_one_generation_sequence(self):
        with self.transaction() as sql:
            manual = self.acquire(sql, mode='file-lock')
            self.assertIsNone(manual['lease_until'])
            self.assertEqual(manual['state'], 'active')
            checkout = self.acquire(sql, replace_generation=int(manual['generation']))
            self.assertGreater(int(checkout['generation']), int(manual['generation']))
            with self.assertRaises(ContractError):
                self.store.release(sql, **self.target, actor='employee', guard_id=manual['guard_id'], generation=int(manual['generation']))

    def test_prepared_intent_persists_until_native_publication(self):
        with self.transaction() as sql:
            guard = self.acquire(sql)
            intent = self.prepare(sql, self.proof(guard))
        with self.transaction() as sql:
            self.assertEqual(self.store.intent(sql, uid=self.target['uid'], intent_id=intent['intent_id'])['state'], 'prepared')
            self.assertEqual(self.store.load(sql, **self.target)['pending_intent'], intent['intent_id'])

    def test_native_failure_rolls_back_content_receipt_and_release_together(self):
        def crash(sql):
            raise RuntimeError('crash after native CAS')
        with self.transaction() as sql:
            guard = self.acquire(sql)
            intent = self.prepare(sql, self.proof(guard), action='checkin')
        with self.assertRaises(RuntimeError), self.transaction() as sql:
            self.native_publish(sql, self.proof(guard), intent['intent_id'], after_content=crash)
        with self.transaction() as sql:
            sql.execute('SELECT file_id FROM fixture_content')
            self.assertEqual(sql.fetchone()[0], 'b'*40)
            self.assertEqual(self.store.intent(sql, uid=self.target['uid'], intent_id=intent['intent_id'])['state'], 'prepared')
            self.assertIsNotNone(self.store.load(sql, **self.target)['guard_id'])

    def test_manual_lock_and_checkout_cannot_overlap(self):
        with self.transaction() as sql:
            self.acquire(sql)
            with self.assertRaises(ContractError):
                self.acquire(sql, mode='file-lock')

    def test_native_barrier_queries_share_guard_semantics(self):
        import hashlib
        from cloudfile_extensions.tests.editing_sql import WORKSPACE, checkout_queries
        queries = checkout_queries(WORKSPACE / 'cloudfile-server/common/cf-lock.c', 'cf_edit_guard')
        final = checkout_queries(WORKSPACE / 'cloudfile-server/server/cloudfile-policy.c', 'cf_edit_guard')
        self.assertEqual(len(queries), 2)
        self.assertEqual(len(final), 1)
        path = '/folder/a.docx'
        path_hash = hashlib.sha256(path.encode()).hexdigest()
        for mode, suspended in [('file-lock', False), ('checkout', False), ('checkout', True)]:
            with self.transaction() as sql:
                proof = self.proof(self.acquire(sql, mode))
                if suspended:
                    sql.execute('UPDATE cf_edit_guard SET lease_until=TIMESTAMPADD(SECOND,-1,UTC_TIMESTAMP(6))')
                for query in queries + final:
                    directory = ' LIKE ' in query
                    for actor in ('employee', 'other'):
                        args = (self.target['repo'], '/folder/%') if directory else (self.target['repo'], path_hash, path, actor)
                        sql.execute(query.replace('?', '%s'), args)
                        self.assertEqual(sql.fetchone() is not None, directory or mode != 'file-lock' or actor != 'employee')
                self.store.release(sql, **self.target, actor='admin', guard_id=proof['guard_id'], generation=proof['generation'], management=True, reason='test teardown')

    def test_native_publication_predicate_requires_exact_prepared_checkout(self):
        import hashlib
        from cloudfile_extensions.tests.editing_sql import WORKSPACE, native_intent_query
        query = native_intent_query(WORKSPACE / 'cloudfile-server/server/cloudfile-policy.c')
        path = '/folder/a.docx'
        with self.transaction() as sql:
            guard = self.acquire(sql)
            proof = self.proof(guard)
            intent = self.store.prepare(sql, **self.target, **proof, intent_id=str(uuid4()),
                expected_file_id='b'*40, staged_file_id=None,
                content_digest='e'*64, action='checkin', snapshot=dict(id=str(uuid4()),size=0,source='fixture'))
            params = (self.target['repo'], self.target['uid'], hashlib.sha256(path.encode()).hexdigest(), path,
                guard['guard_id'], guard['generation'], guard['credential_epoch'],
                'employee', 'employee', 'device', hashlib.sha256(('a'*64).encode()).hexdigest(),
                intent['intent_id'], 'b'*40, 'c'*40, 'e'*64, 0)
            sql.execute(query.replace('?', '%s'), params)
            self.assertEqual(sql.fetchall(), (('checkin',),))
            for position, wrong in ((0, str(uuid4())), (1, str(uuid4())),
                                    (3, '/folder/other.docx'), (7, 'other'), (8, 'other'),
                                    (10, 'f'*64), (11, str(uuid4())),
                                    (12, 'f'*40), (14, 'f'*64)):
                changed = list(params)
                changed[position] = wrong
                sql.execute(query.replace('?', '%s'), changed)
                self.assertEqual(sql.fetchall(), ())

    def test_commit_and_management_release_serialize(self):
        from concurrent.futures import ThreadPoolExecutor, TimeoutError
        from threading import Event
        import pymysql
        with self.transaction() as sql:
            proof = self.proof(self.acquire(sql))
            intent = self.prepare(sql, proof)
        entered = Event()
        def reclaim():
            connection = pymysql.connect(**self.options, database=self.database)
            try:
                connection.begin()
                with connection.cursor() as sql:
                    entered.set()
                    self.store.release(sql, **self.target, actor='admin', guard_id=proof['guard_id'], generation=proof['generation'], management=True, reason='operator recovery')
                connection.commit()
            finally:
                connection.rollback()
                connection.close()
        pool = ThreadPoolExecutor(max_workers=1)
        try:
            with self.transaction() as sql:
                self.native_publish(sql, proof, intent['intent_id'])
                future = pool.submit(reclaim)
                self.assertTrue(entered.wait(3))
                with self.assertRaises(TimeoutError):
                    future.result(timeout=0.2)
            future.result(timeout=5)
            with self.transaction() as sql:
                self.assertEqual(self.store.intent(sql, uid=self.target['uid'], intent_id=intent['intent_id'])['state'], 'published')
                self.assertIsNone(self.store.load(sql, **self.target)['guard_id'])
        finally:
            pool.shutdown(wait=True)

    def test_unchanged_checkin_and_manual_unlock(self):
        with self.transaction() as sql:
            guard = self.acquire(sql)
            proof = self.proof(guard)
            intent = self.store.prepare(sql, **self.target, **proof,
                intent_id=str(uuid4()), expected_file_id='b' * 40,
                staged_file_id='b' * 40,
                content_digest=hashlib.sha256(b'').hexdigest(), action='checkin-unchanged')
            self.native_publish(sql, proof, intent['intent_id'])
            manual = self.acquire(sql, mode='file-lock')
            result = self.store.release(sql, **self.target, actor='employee', guard_id=manual['guard_id'], generation=int(manual['generation']))
            self.assertFalse(result['active'])

    def test_unchanged_checkin_refuses_drift_and_keeps_guard_and_intent(self):
        with self.transaction() as sql:
            guard = self.acquire(sql)
            proof = self.proof(guard)
            intent = self.store.prepare(sql, **self.target, **proof,
                intent_id=str(uuid4()), expected_file_id='b' * 40,
                staged_file_id='b' * 40,
                content_digest=hashlib.sha256(b'').hexdigest(), action='checkin-unchanged')
            sql.execute('UPDATE fixture_content SET file_id=%s WHERE repo=%s', ('f' * 40, self.target['repo']))
        with self.assertRaises(ContractError):
            with self.transaction() as sql:
                self.native_publish(sql, proof, intent['intent_id'])
        with self.transaction() as sql:
            self.assertEqual(self.store.intent(sql, uid=self.target['uid'], intent_id=intent['intent_id'])['state'], 'prepared')
            self.assertEqual(self.store.load(sql, **self.target)['pending_intent'], intent['intent_id'])
            self.assertEqual(self.store.load(sql, **self.target)['guard_id'], guard['guard_id'])

    def test_hard_expiry_requires_explicit_recovery_and_reason(self):
        with self.transaction() as sql:
            guard = self.acquire(sql)
            sql.execute('UPDATE cf_edit_guard SET hard_expire_at=TIMESTAMPADD(SECOND,-1,UTC_TIMESTAMP(6))')
            with self.assertRaises(ContractError):
                self.store.resume(sql, **self.target, actor='employee', guard_id=guard['guard_id'], generation=1, credential_epoch=1,
                                  holder='new-device', token='f'*64, expected_file_id='b'*40)
            with self.assertRaises(ValueError):
                self.store.release(sql, **self.target, actor='admin', guard_id=guard['guard_id'], generation=1, management=True)
            released = self.store.release(sql, **self.target, actor='admin', guard_id=guard['guard_id'], generation=1, management=True, reason='Owner recovery')
            self.assertFalse(released['active'])

    def test_expiry_during_native_publication_rolls_back(self):
        def expire(sql):
            sql.execute('UPDATE cf_edit_guard SET lease_until=TIMESTAMPADD(SECOND,-1,UTC_TIMESTAMP(6))')
        with self.transaction() as sql:
            guard = self.acquire(sql)
            intent = self.prepare(sql, self.proof(guard))
        with self.assertRaises(ContractError), self.transaction() as sql:
            self.native_publish(sql, self.proof(guard), intent['intent_id'], after_content=expire)
        with self.transaction() as sql:
            sql.execute('SELECT file_id FROM fixture_content')
            self.assertEqual(sql.fetchone()[0], 'b'*40)

    def test_intent_identity_cannot_be_reused_for_different_content(self):
        with self.transaction() as sql:
            proof = self.proof(self.acquire(sql))
            intent = self.prepare(sql, proof)
            with self.assertRaises(ContractError) as caught:
                self.store.prepare(sql, **self.target, **proof, intent_id=intent['intent_id'],
                    expected_file_id='b' * 40, staged_file_id='f' * 40, content_digest='e' * 64, action='commit')
            self.assertEqual(caught.exception.code, 'IDEMPOTENCY_CONFLICT')

    def test_native_baseline_conflict_preserves_pending_local_work(self):
        with self.transaction() as sql:
            proof = self.proof(self.acquire(sql))
            intent = self.prepare(sql, proof)
            sql.execute('UPDATE fixture_content SET file_id=%s', ('f' * 40,))
        with self.assertRaises(ContractError), self.transaction() as sql:
            self.native_publish(sql, proof, intent['intent_id'])
        with self.transaction() as sql:
            self.assertEqual(self.store.load(sql, **self.target)['pending_intent'], intent['intent_id'])
            self.assertEqual(self.store.intent(sql, uid=self.target['uid'], intent_id=intent['intent_id'])['state'], 'prepared')
