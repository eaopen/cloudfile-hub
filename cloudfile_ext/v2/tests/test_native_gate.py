# -*- coding: utf-8 -*-
import unittest
from types import SimpleNamespace

from cloudfile_ext.v2 import native_gate


def decision(permission):
    return SimpleNamespace(permission=permission, can_read=permission in ('r', 'rw'))


class FakeAuthority(object):
    def __init__(self, value=None, error=None):
        self._value = value
        self._error = error
        self.calls = []

    def effective(self, repo_id, path, kind='dir'):
        self.calls.append((repo_id, path, kind))
        if self._error:
            raise self._error
        return self._value


class NativeGateTests(unittest.TestCase):
    """Seahub 写入口拿到的必须是 V2 决策，而不是原始 native 结论。"""

    def run_gate(self, native, acl_permission, error=None):
        authority = FakeAuthority(decision(acl_permission), error)
        original = native_gate._authority
        native_gate._authority = lambda username: authority
        try:
            return native_gate.check_permission('u@x', 'r' * 36, '/dir', native), authority
        finally:
            native_gate._authority = original

    def test_directory_rule_raises_library_read_to_write(self):
        self.assertEqual(self.run_gate('r', 'rw')[0], 'rw')

    def test_directory_rule_narrows_library_write(self):
        self.assertEqual(self.run_gate('rw', 'r')[0], 'r')

    def test_invisible_denies(self):
        self.assertIsNone(self.run_gate('r', 'invisible')[0])

    def test_every_native_verdict_uses_the_authority(self):
        for permission in ('admin', 'custom-share', None):
            self.assertIsNone(self.run_gate(permission, 'invisible')[0])
            self.assertEqual(self.run_gate(permission, 'rw')[0], 'rw')

    def test_runtime_error_refuses_native_fallback(self):
        from cloudfile_ext.v2.acl_runtime import ACLUnavailable
        with self.assertRaises(ACLUnavailable):
            self.run_gate('rw', None, error=RuntimeError('acl down'))

    def test_inactive_or_missing_subject_remains_a_denial(self):
        self.assertIsNone(self.run_gate('rw', None, error=PermissionError())[0])

    def test_path_is_evaluated_as_a_directory(self):
        _, authority = self.run_gate('r', 'rw')
        self.assertEqual(authority.calls, [('r' * 36, '/dir', 'dir')])


if __name__ == '__main__':
    unittest.main()


class PathNormalisationTests(unittest.TestCase):
    """Seahub passes '/dir/' while the policy core only accepts '/dir'."""

    def test_trailing_and_duplicate_slashes_are_normalised(self):
        import cloudfile_ext.v2.native_gate as gate
        from cloudfile_ext.v2.acl_policy import canonical_path
        for raw, expected in (('/a/', '/a'), ('/a//b/', '/a/b'), ('/', '/'), ('', '/')):
            self.assertEqual(canonical_path(gate._canonical(raw)), expected)

    def test_traversal_is_rejected(self):
        import cloudfile_ext.v2.native_gate as gate
        with self.assertRaises(ValueError):
            gate._canonical('/a/../b')
