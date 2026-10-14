"""Hub and Server consume one scoped policy matrix using the real C library."""
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import tempfile
import unittest
from uuid import uuid4

from cloudfile_extensions.authorization.core import PolicyCore
from cloudfile_extensions.authorization.shares import share_value
from cloudfile_extensions.common.errors import ContractError

WORKSPACE = Path(__file__).resolve().parents[3]


class ScopedPolicyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='cf-scoped-hub-')
        cls.addClassCleanup(cls.temp.cleanup)
        library = Path(cls.temp.name) / 'acl.so'
        subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-shared', '-fPIC',
            str(Path(os.environ.get('CF_TEST_SERVER_ROOT', WORKSPACE / 'cloudfile-server')) / 'server/cloudfile-acl.c'), '-o', str(library)], check=True)
        cls.core = PolicyCore(str(library))
        cls.vectors = json.loads((Path(os.environ.get('CF_TEST_DOCKER_ROOT', WORKSPACE / 'cloudfile-docker')) / 'docs/directory-access-v09-cases.json').read_text())

    def test_shared_matrix(self):
        for case in self.vectors['cases']:
            v = {**self.vectors['defaults'], **case['input']}
            # Barrier and readiness enforcement belongs to the authority, not
            # the ctypes adapter; those cases run directly against C.
            if v['barrier_active'] or not v['context_ready']:
                continue
            def subject(type_, id_):
                return dict(type=type_, provider='directory', namespace='user' if type_ == 'user' else 'test', external_id=id_)
            actor = dict(userId=v['userId'], status='active' if v['account_active'] else 'disabled', attributes={},
                organizations=[dict(namespace='test', external_id=d, is_primary=False) for d in v['departments']],
                roles=[dict(namespace='test', external_id=g) for g in v['groups']], etag='test',
                generated_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))
            rules = [dict(path=r['path'], kind=r.get('kind', 'dir'), inherit=r['inherit'], permission=r['permission'],
                subject=subject(r['subject_type'], r['subject_id'])) for r in v['rules']]
            shares = [dict(path=s['path'], subject=subject(s['subject_type'], s['subject_id'])) for s in v['shares']]
            ref = dict(repo_id=str(uuid4()), **v['target'])
            with self.subTest(case=case['id']):
                result = self.core.evaluate_scoped(ref, provider='directory', subject=actor,
                    rules=rules, ce_permission=v['ce_permission'], directory_shares=shares,
                    hard_readonly=v['repo_hard_readonly'])
                self.assertEqual(result, case['expected'])
                if v['ce_permission'] is None:
                    self.assertEqual(self.core.evaluate(ref, provider='directory', subject=actor,
                        rules=rules, ce_permission=None), dict(visible=False, read=False, write=False))

    def test_share_never_accepts_an_acl_permission(self):
        value = dict(path='/team', subject=dict(type='user', provider='directory', namespace='user', external_id='u1'))
        self.assertEqual(share_value(value), value)
        for changes in (dict(permission='rw'), dict(inherit=False), dict(path='/')):
            with self.assertRaises(ContractError):
                share_value({**value, **changes})


if __name__ == '__main__':
    unittest.main()
