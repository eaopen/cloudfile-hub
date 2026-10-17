"""Runtime policy and new machine JWT configuration: per UID, bounded TTL."""
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from cloudfile_ext.v2 import runtime
from cloudfile_ext.v2.errors import IdentityUnavailable, SubjectNotBound

def settings(**values):
    return SimpleNamespace(**values)

def directory_settings(**values):
    base = dict(CF_DIRECTORY_URL='https://directory.example.test/directory',
                CF_DIRECTORY_AUTH_KEY_ID='kid',
                CF_DIRECTORY_AUTH_SECRET='x'*40)
    base.update(values)
    return settings(**base)


class ConfigurationTest(unittest.TestCase):
    def test_ce_only_deployment_is_inert(self):
        self.assertIsNone(runtime.configuration(settings()))
        self.assertIsNone(runtime.configuration(settings(CF_DIRECTORY_URL='')))
    def test_incomplete_jwt_connection_is_rejected(self):
        for values in ({'CF_DIRECTORY_URL':'https://directory.example.test'},
                       {'CF_DIRECTORY_AUTH_SECRET':'x'*40},
                       {'CF_DIRECTORY_URL':'http://directory.example.test/directory',
                        'CF_DIRECTORY_AUTH_KEY_ID':'kid','CF_DIRECTORY_AUTH_SECRET':'x'*40},
                       {'CF_DIRECTORY_URL':'https://directory.example.test/directory',
                        'CF_DIRECTORY_AUTH_KEY_ID':'kid','CF_DIRECTORY_AUTH_SECRET':'short'}):
            with self.subTest(values=values),self.assertRaises(IdentityUnavailable):
                runtime.configuration(settings(**values))
    def test_one_consistent_bounded_ttl(self):
        cfg=runtime.configuration(directory_settings())
        self.assertEqual((cfg['provider'],cfg['ttl'],cfg['issuer'],cfg['audience']),
                         ('etech',1800,'cloudfile-sso','eap-directory'))
        for ttl in (30,60,1800):
            self.assertEqual(runtime.configuration(directory_settings(CF_SUBJECT_TTL=ttl))['ttl'],ttl)
        for ttl in (29,1801,3600,True,'1800'):
            with self.subTest(ttl=ttl),self.assertRaises(IdentityUnavailable):
                runtime.configuration(directory_settings(CF_SUBJECT_TTL=ttl))


class StubProjector:
    def __init__(self, error=None):
        self.calls, self.error = [], error

    def ensure(self, uid, username, *, force=False):
        self.calls.append((uid, username, force))
        if self.error is not None:
            raise self.error


def membership_runtime(error=None):
    projector = StubProjector(error)
    config = {'url': 'https://directory.example.test/directory', 'token': 'token',
              'provider': 'etech', 'ttl': 1800, 'timeout': 5, 'insecure': False}
    return runtime.MembershipRuntime(config, projector_factory=lambda *args: projector,
                                     redis_factory=object,
                                     fetch_factory=lambda parsed: parsed['url']), projector


class MembershipRuntimeTest(unittest.TestCase):
    def test_login_publishes_a_fresh_subject_and_requests_reuse_the_ttl(self):
        subject_runtime, projector = membership_runtime()
        subject_runtime.prepare_subject('user@auth.local', 'uid-1')
        subject_runtime.require_ready('user@auth.local', 'uid-1')
        self.assertEqual(projector.calls, [('uid-1', 'user@auth.local', True),
                                           ('uid-1', 'user@auth.local', False)])

    def test_missing_stable_uid_is_never_projected(self):
        subject_runtime, projector = membership_runtime()
        for uid in ('', None):
            with self.subTest(uid=uid), self.assertRaises(SubjectNotBound):
                subject_runtime.prepare_subject('user@auth.local', uid)
            with self.subTest(uid=uid), self.assertRaises(SubjectNotBound):
                subject_runtime.require_ready('user@auth.local', uid)
        self.assertEqual(projector.calls, [])

    def test_refresh_failure_is_never_downgraded_to_a_pass(self):
        for error in (IdentityUnavailable('directory down'), SubjectNotBound('no uid')):
            with self.subTest(error=type(error).__name__):
                subject_runtime, _ = membership_runtime(error)
                with self.assertRaises(IdentityUnavailable):
                    subject_runtime.require_ready('user@auth.local', 'uid-1')


class StubRuntime:
    def __init__(self):
        self.prepared, self.ready = [], []

    def prepare_subject(self, username, uid):
        self.prepared.append((username, uid))

    def require_ready(self, username, uid):
        self.ready.append((username, uid))


class AdapterTest(unittest.TestCase):
    def test_disabled_deployment_is_inert_for_login_and_requests(self):
        offline = settings()
        self.assertFalse(runtime.prepare_subject('user@auth.local', 'uid-1', settings=offline))
        self.assertFalse(runtime.require_ready('user@auth.local', settings=offline))

    def test_login_and_request_share_one_uid_subject(self):
        stub = StubRuntime()
        configured = directory_settings()
        with patch.object(runtime, '_runtime_for', return_value=stub), \
                patch.object(runtime, 'bound_uid', return_value='uid-1'):
            self.assertTrue(runtime.prepare_subject('user@auth.local', 'uid-1', settings=configured))
            self.assertTrue(runtime.require_ready('user@auth.local', settings=configured))
        self.assertEqual(stub.prepared, [('user@auth.local', 'uid-1')])
        self.assertEqual(stub.ready, [('user@auth.local', 'uid-1')])

    def test_unbound_native_account_stays_closed(self):
        with patch.object(runtime, '_runtime_for', return_value=StubRuntime()), \
                patch.object(runtime, 'bound_uid', side_effect=SubjectNotBound('no uid')):
            with self.assertRaises(SubjectNotBound):
                runtime.require_ready('user@auth.local', settings=directory_settings())


if __name__ == '__main__':
    unittest.main()
