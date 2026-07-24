# -*- coding: utf-8 -*-
from unittest import TestCase

from cloudfile_ext.audit.service import VALID_OBJECTS, VALID_OPS, filters


class AuditFilterTests(TestCase):

    def test_filters_accept_file_and_directory_operation_contract(self):
        clauses, values = filters({
            'repo_id': 'repo', 'user': 'u@example.com',
            'op_type': 'rename', 'obj_type': 'dir',
        })
        self.assertEqual(
            clauses,
            ['repo_id = %s', 'op_user = %s', 'op_type = %s', 'obj_type = %s'])
        self.assertEqual(values, ['repo', 'u@example.com', 'rename', 'dir'])

    def test_operation_and_object_contracts_are_explicit(self):
        self.assertIn('move', VALID_OPS)
        self.assertIn('file', VALID_OBJECTS)
        self.assertIn('dir', VALID_OBJECTS)
        with self.assertRaises(ValueError):
            filters({'op_type': 'download'})
        with self.assertRaises(ValueError):
            filters({'obj_type': 'repo'})

    def test_default_list_is_scoped_to_files_and_directories(self):
        clauses, values = filters({})
        self.assertEqual(clauses, ['obj_type IN (%s, %s)'])
        self.assertEqual(values, ['file', 'dir'])
