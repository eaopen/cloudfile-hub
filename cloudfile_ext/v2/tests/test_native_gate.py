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

    def test_admin_and_custom_permissions_are_untouched(self):
        for permission in ('admin', 'custom-share'):
            self.assertEqual(self.run_gate(permission, 'rw')[0], permission)

    def test_runtime_error_keeps_the_native_verdict(self):
        value, _ = self.run_gate('rw', None, error=RuntimeError('acl down'))
        self.assertEqual(value, 'rw')

    def test_path_is_evaluated_as_a_directory(self):
        _, authority = self.run_gate('r', 'rw')
        self.assertEqual(authority.calls, [('r' * 36, '/dir', 'dir')])


if __name__ == '__main__':
    unittest.main()
