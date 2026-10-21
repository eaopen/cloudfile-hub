"""Real isolated retention SQL with an explicit native-session table fixture.

Does not prove Django signing, live database co-location or deployed execution.
"""
from cloudfile_extensions.identity.session_index import OIDCSessionIndex
from cloudfile_extensions.identity.session_delete import NativeDBSessionDelete
from cloudfile_extensions.identity.session_retention import OIDCSessionRetention
from cloudfile_extensions.identity.logout_token import LogoutNotification
from cloudfile_extensions.schema.runner import SchemaRunner
from cloudfile_extensions.tests.test_schema import DatabaseTestCase


class SessionRetentionTests(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        SchemaRunner(self.connection).apply()
        self.index = OIDCSessionIndex(self.connection, issuer="https://idp.invalid/", client_id="cloudfile")
        # Only this isolated schema's fixture is used. Do not bypass adapter
        # construction in runtime code or call this a real Django integration.
        deletion = object.__new__(NativeDBSessionDelete)
        deletion.index = self.index
        deletion.table = "cf_test_native_sessions"
        self.retention = OIDCSessionRetention(deletion)
        with self.connection.cursor() as cursor:
            cursor.execute("CREATE TABLE cf_test_native_sessions(session_key VARCHAR(40) PRIMARY KEY,expire_date DATETIME(6)) ENGINE=InnoDB")

    def reference(self, cursor, key, *, expired=True, scope=None):
        cursor.execute("INSERT INTO cf_oidc_session(scope_hash,session_key,subject_hash,sid_hash,authenticated_at,expires_at) "
            "VALUES(%s,%s,%s,NULL,1," + ("UTC_TIMESTAMP(6)-INTERVAL 1 DAY" if expired else
            "UTC_TIMESTAMP(6)+INTERVAL 1 DAY") + ")", (scope or self.index.scope_hash, key * 32, "a" * 64))

    def test_missing_and_expired_removed_but_live_and_other_scope_retained(self):
        with self.connection.cursor() as cursor:
            for key in "abc":
                self.reference(cursor, key)
            self.reference(cursor, "d", expired=False)
            self.reference(cursor, "e", scope="f" * 64)
            cursor.execute("INSERT INTO cf_test_native_sessions VALUES(%s,UTC_TIMESTAMP(6)-INTERVAL 1 DAY),"
                "(%s,UTC_TIMESTAMP(6)+INTERVAL 1 DAY)", ("b" * 32, "c" * 32))
        self.connection.begin()
        with self.connection.cursor() as cursor:
            self.index.fence(cursor, LogoutNotification(self.index.issuer, self.index.client_id,
                "jti", "subject", None, 1000, 1060))
        self.connection.commit()
        self.assertEqual(self.retention.run_once(), dict(examined=3, removed=2, renewed=1))
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT session_key FROM cf_oidc_session ORDER BY session_key")
            self.assertEqual(cursor.fetchall(), tuple((key * 32,) for key in "cde"))
            cursor.execute("SELECT COUNT(*) FROM cf_test_native_sessions")
            self.assertEqual(cursor.fetchone(), (2,))
            cursor.execute("SELECT cutoff_at FROM cf_oidc_logout_fence")
            self.assertEqual(cursor.fetchall(), ((1000,),))

    def test_page_budget_and_repeated_cleanup(self):
        with self.connection.cursor() as cursor:
            for key in "abc":
                self.reference(cursor, key)
        self.assertEqual(self.retention.run_once(limit=2)["removed"], 2)
        self.assertEqual(self.retention.run_once(limit=2)["removed"], 1)
        self.assertEqual(self.retention.run_once(limit=2)["examined"], 0)
        for limit in (0, 101, True):
            with self.assertRaises(ValueError):
                self.retention.run_once(limit=limit)
