"""Actual SQL/Redis provisioning recovery; directory transport is a fixture."""
from datetime import datetime, timezone
import os
import unittest
from unittest.mock import Mock
from uuid import uuid4

from cloudfile_extensions.directory.preparation import SubjectPreparation
from cloudfile_extensions.directory.provider import DirectoryProvider
from cloudfile_extensions.identity.jit import SQLJITProvisioner
from cloudfile_extensions.identity.provisioning import ProvisioningJobs
from cloudfile_extensions.identity.sql_bindings import SQLIdentityBindings
from cloudfile_extensions.jobs.store import JobStore
from cloudfile_extensions.jobs.worker import JobWorker
from cloudfile_extensions.schema.runner import SchemaRunner
from cloudfile_extensions.tests.test_schema import DatabaseTestCase


@unittest.skipUnless(os.environ.get("CF_TEST_REDIS_PORT"), "requires isolated Redis")
class ProvisioningTest(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        import redis
        self.redis = redis.Redis(host=os.environ.get("CF_TEST_REDIS_HOST", "127.0.0.1"), port=int(os.environ["CF_TEST_REDIS_PORT"]))
        SchemaRunner(self.connection).apply()
        self.native, self.identity = "cf_jit_native_" + uuid4().hex, "cf_jit_hub_" + uuid4().hex
        with self.admin.cursor() as cursor:
            cursor.execute("CREATE DATABASE " + self.native)
            cursor.execute("CREATE DATABASE " + self.identity)
            cursor.execute("CREATE TABLE " + self.native + ".EmailUser(id BIGINT AUTO_INCREMENT PRIMARY KEY,email VARCHAR(255) UNIQUE,passwd VARCHAR(256),is_active TINYINT NOT NULL,is_staff TINYINT NOT NULL,ctime BIGINT) ENGINE=InnoDB")
            cursor.execute("CREATE TABLE " + self.native + ".`Group`(group_id INT PRIMARY KEY,parent_group_id INT) ENGINE=InnoDB")
            cursor.execute("CREATE TABLE " + self.native + ".GroupUser(group_id INT,user_name VARCHAR(255),is_staff TINYINT,UNIQUE KEY member(group_id,user_name)) ENGINE=InnoDB")
            cursor.execute("CREATE TABLE " + self.identity + ".profile_profile(user VARCHAR(254) UNIQUE,login_id VARCHAR(225) UNIQUE,nickname VARCHAR(64),intro TEXT,lang_code TEXT,contact_email VARCHAR(225) UNIQUE,is_manually_set_contact_email TINYINT,institution VARCHAR(225),list_in_address_book TINYINT) ENGINE=InnoDB")
            cursor.execute("CREATE TABLE " + self.identity + ".social_auth_usersocialauth(id BIGINT AUTO_INCREMENT PRIMARY KEY,username VARCHAR(255),provider VARCHAR(32),uid VARCHAR(255),extra_data TEXT,UNIQUE KEY binding(provider,uid)) ENGINE=InnoDB")
        self.transport = Mock()
        self.transport.get.return_value = dict(userId="u1", status="active", attributes={}, organizations=[], roles=[],
            etag="latest", generated_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))
        self.directory = DirectoryProvider("https://directory.example.invalid/v2", authorization=lambda: "Bearer fixture",
                                           attribute_allowlist=(), client=self.transport)
        bindings = SQLIdentityBindings(self.connection, native_schema=self.native, identity_schema=self.identity,
            directory_provider="directory", authorize=lambda *args: False, audit=lambda *args: None)
        self.claims = dict(issuer="https://idp.example.invalid/", sub="stable-sub", userId="u1")
        jit = SQLJITProvisioner(bindings, issuer=self.claims["issuer"], directory=self.directory, enabled=True, request_id="jit-recovery")
        self.prefix = "cf:test:" + uuid4().hex + ":"
        self.fail_preparation = False
        def preparation(user):
            if self.fail_preparation:
                raise RuntimeError("fixture source preparation outage")
            return SubjectPreparation(self.connection, self.redis, provider_id="directory", directory=self.directory,
                native_schema=self.native, identity_schema=self.identity, actor_user_id=user, request_id="recovery",
                prefix=self.prefix)
        self.pipeline = ProvisioningJobs(JobStore(self.connection), jit, preparation_factory=preparation)
        self.worker = JobWorker(self.pipeline.store, owner="jit-test", handlers={self.pipeline.KIND: self.pipeline.handler})

    def tearDown(self):
        keys = list(self.redis.scan_iter(match=self.prefix + "*"))
        if keys:
            self.redis.delete(*keys)
        self.redis.close()
        with self.admin.cursor() as cursor:
            cursor.execute("DROP DATABASE " + self.native)
            cursor.execute("DROP DATABASE " + self.identity)
        super().tearDown()

    def test_resume_identity_created_failure_without_second_account(self):
        job, created = self.pipeline.submit(self.claims)
        self.assertTrue(created)
        import time
        from cloudfile_extensions.common.errors import ContractError
        status_identity = {**self.claims, "expires_at": int(time.time()) + 300}
        self.assertEqual(self.pipeline.status_for_login(status_identity, job),
                         dict(job_id=job, status="queued", retryable=False))
        from cloudfile_extensions.identity.pending import PendingLoginProofs, PendingLoginStatus
        proofs = PendingLoginProofs(self.redis, prefix=self.prefix)
        token = proofs.issue(status_identity, job, "browser-binding-" * 3)
        self.assertEqual(PendingLoginStatus(proofs, self.pipeline).status(token, "browser-binding-" * 3),
                         dict(job_id=job, status="queued", retryable=False))
        with self.assertRaises(ContractError) as caught:
            self.pipeline.status_for_login({**status_identity, "sub": "other-sub"}, job)
        self.assertEqual(caught.exception.status, 404)
        self.fail_preparation = True
        self.assertEqual(self.worker.run_once(), job)
        self.assertEqual(self.pipeline.store.get(job)["status"], "failed")
        self.assertEqual(self.pipeline.status_for_login(status_identity, job),
                         dict(job_id=job, status="failed", retryable=True))
        self.assertEqual(self.pipeline.submit(self.claims), (job, False))
        # Fresh verified identity fixture, not an anonymous retry endpoint.
        self.assertEqual(self.pipeline.request_for_login(self.claims, unbound=False), job)
        self.fail_preparation = False
        self.assertEqual(self.worker.run_once(), job)
        self.assertEqual(self.pipeline.store.get(job)["status"], "succeeded")
        self.assertIsNone(self.pipeline.request_for_login(self.claims, unbound=False))
        with self.admin.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM " + self.native + ".EmailUser")
            self.assertEqual(cursor.fetchone()[0], 1)
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM cf_audit_event WHERE operation='identity.created'")
            self.assertEqual(cursor.fetchone()[0], 1)

    def test_cancel_during_source_read_cannot_finish_or_publish_ready(self):
        job, _ = self.pipeline.submit(self.claims)
        original = self.transport.get.return_value
        calls = 0
        def fetch(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.pipeline.store.cancel(job, actor="admin", actor_kind="user")
            return original
        self.transport.get.side_effect = fetch
        self.worker.run_once()
        self.assertEqual(self.pipeline.store.get(job)["status"], "cancelled")
        from cloudfile_extensions.common.errors import ContractError
        with self.assertRaises(ContractError) as caught:
            self.pipeline.request_for_login(self.claims, unbound=False)
        self.assertEqual(caught.exception.code, "PROVISIONING_CANCELLED")
        self.assertEqual(self.pipeline.store.retry_failed(job, actor="u1", actor_kind="user")["status"], "cancelled")
        values = [self.redis.get(key) for key in self.redis.scan_iter(match=self.prefix + "*")]
        self.assertFalse(any(b'"status": "ready"' in value for value in values if value))

    def runtime(self, **options):
        from cloudfile_extensions.identity.runtime import LoginRuntime
        from cloudfile_extensions.identity.oidc import OIDCConfig
        oidc = OIDCConfig(issuer=self.claims["issuer"], client_id="cloudfile",
            client_secret="fixture-secret", redirect_uri="https://files.example.invalid/callback",
            authorization_url=self.claims["issuer"] + "authorize",
            token_url=self.claims["issuer"] + "token", userinfo_url=self.claims["issuer"] + "userinfo",
            jwks_url=self.claims["issuer"] + "jwks")
        return LoginRuntime(self.connection, self.redis, oidc=oidc, directory=self.directory,
            provider_id="directory", native_schema=self.native, identity_schema=self.identity,
            request_id="runtime-test", prefix=self.prefix, **options)

    def test_runtime_worker_real_adapters_prepare_and_proof_status(self):
        from django.conf import settings
        if not settings.configured:
            settings.configure(DEFAULT_CHARSET="utf-8")
        from django.http import HttpResponse
        import time
        runtime = self.runtime(jit_enabled=True)
        request = Mock()
        request.is_secure.return_value = True
        request.COOKIES = {}
        response = HttpResponse()
        binding = runtime.browser.rotate(request, response)
        url = runtime.login.begin(binding, redirect="/files/")
        self.assertIn("code_challenge=", url)
        self.assertIn("state=", url)
        job = runtime.provisioning.request_for_login(self.claims, unbound=True)
        identity = {**self.claims, "expires_at": int(time.time()) + 300}
        token = runtime.proofs.issue(identity, job, binding)
        self.assertEqual(runtime.pending.status(token, binding)["status"], "queued")
        worker = JobWorker(runtime.store, owner="runtime-worker",
            handlers={runtime.provisioning.KIND: runtime.provisioning.handler})
        self.assertEqual(worker.run_once(), job)
        self.assertEqual(runtime.pending.status(token, binding)["status"], "succeeded")
        context = runtime.preparation("u1").prepare("u1")
        self.assertEqual(context["status"], "ready")
        self.assertIs(runtime.jit.bindings.connection, runtime.store.connection)
        self.assertIs(runtime.proofs.redis, runtime.browser.redis)
        runtime.browser.clear(binding, response)
        from cloudfile_extensions.common.errors import ContractError
        with self.assertRaises(ContractError):
            runtime.pending.status(token, binding)

    def test_runtime_defaults_deny_jit_management_and_invalid_flag(self):
        from cloudfile_extensions.common.errors import ContractError
        runtime = self.runtime()
        with self.assertRaises(ContractError) as caught:
            runtime.provisioning.request_for_login(self.claims, unbound=True)
        self.assertEqual(caught.exception.status, 403)
        with self.assertRaises(ContractError):
            runtime.bindings.authorize(None, "u1", "u1", "native")
        with self.assertRaises(ValueError):
            self.runtime(jit_enabled="true")
