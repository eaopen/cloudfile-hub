# -*- coding: utf-8 -*-
import datetime
import json
from unittest import TestCase

from cloudfile_ext.audit.events import tag_snapshot
from cloudfile_ext.audit.service import (
    VALID_OBJECTS, VALID_OPS, activity_where, merge_and_paginate,
    parse_filters, serialize_activity, serialize_audit_event,
)


def _dt(s):
    return datetime.datetime.strptime(s, '%Y-%m-%dT%H:%M:%S')


class AuditFilterTests(TestCase):

    def test_parse_filters_accepts_file_and_directory_operation_contract(self):
        spec = parse_filters({
            'repo_id': 'repo', 'user': 'u@example.com',
            'op_type': 'rename', 'obj_type': 'dir',
        })
        self.assertEqual(spec['repo_id'], 'repo')
        self.assertEqual(spec['user'], 'u@example.com')
        self.assertEqual(spec['op_type'], 'rename')
        self.assertEqual(spec['obj_type'], 'dir')
        self.assertIsNone(spec['source'])
        self.assertIsNone(spec['result'])

    def test_operation_object_source_and_result_contracts_are_explicit(self):
        self.assertIn('move', VALID_OPS)
        self.assertIn('update', VALID_OPS)  # tag rename/recolour
        self.assertIn('file', VALID_OBJECTS)
        self.assertIn('dir', VALID_OBJECTS)
        self.assertIn('tag', VALID_OBJECTS)
        for bad in ({'op_type': 'download'}, {'obj_type': 'repo'},
                    {'source': 'unknown'}, {'result': 'partial'}):
            with self.assertRaises(ValueError):
                parse_filters(bad)

    def test_time_filters_accept_epoch_and_iso(self):
        self.assertEqual(parse_filters({'start': '0'})['start'],
                         _dt('1970-01-01T00:00:00'))
        self.assertEqual(parse_filters({'end': '2026-08-15T10:00:00'})['end'],
                         _dt('2026-08-15T10:00:00'))
        with self.assertRaises(ValueError):
            parse_filters({'start': 'not-a-time'})
        with self.assertRaises(ValueError):
            parse_filters({'start': '2026-08-15', 'end': '2026-08-14'})

    def test_activity_where_default_list_is_scoped_to_files_and_dirs(self):
        clauses, values = activity_where(parse_filters({}))
        self.assertEqual(clauses, ['obj_type IN (%s, %s)'])
        self.assertEqual(values, ['file', 'dir'])

    def test_activity_where_builds_all_supported_clauses(self):
        spec = parse_filters({
            'repo_id': 'repo', 'user': 'u@example.com', 'op_type': 'rename',
            'obj_type': 'dir', 'path': '/a', 'start': '0', 'end': '9999999999',
        })
        clauses, values = activity_where(spec)
        self.assertEqual(clauses, [
            'repo_id = %s', 'op_user = %s', 'op_type = %s', 'obj_type = %s',
            '(path LIKE %s OR detail LIKE %s)', 'timestamp >= %s',
            'timestamp <= %s'])
        self.assertEqual(values[:4], ['repo', 'u@example.com', 'rename', 'dir'])

    def test_activity_where_maps_source_and_result_to_commit_success(self):
        # commit/success are Activity's implicit values -> no extra clause.
        self.assertEqual(activity_where(parse_filters({'source': 'commit'})),
                         (['obj_type IN (%s, %s)'], ['file', 'dir']))
        self.assertEqual(activity_where(parse_filters({'result': 'success'})),
                         (['obj_type IN (%s, %s)'], ['file', 'dir']))
        # Any other source/result cannot match an Activity row.
        clauses, _ = activity_where(parse_filters({'source': 'api'}))
        self.assertIn('1 = 0', clauses)
        clauses, _ = activity_where(parse_filters({'result': 'failure'}))
        self.assertIn('1 = 0', clauses)


class AuditSerializationTests(TestCase):

    def test_serialize_activity_single_and_batch_detail(self):
        single = serialize_activity((
            1, 'rename', 'dir', 'u@example.com', _dt('2026-08-15T10:00:00'),
            'repo', 'commit', '/new', '{"old_path": "/old"}'))
        self.assertEqual(single['event_id'], 'activity-1')
        self.assertEqual(single['source'], 'commit')
        self.assertEqual(single['result'], 'success')
        self.assertEqual(single['old_path'], '/old')
        self.assertEqual(single['path'], '/new')

        batch = serialize_activity((
            2, 'batch_create', 'file', 'u@example.com',
            _dt('2026-08-15T10:00:00'), 'repo', 'commit', '/a',
            json.dumps([{'old_path': '/old-a'}, {'old_path': '/old-b'}])))
        self.assertEqual(batch['old_path'], '/old-a')

    def test_serialize_audit_event_carries_before_after(self):
        row = (
            7, 'repo', 'tag', '12', 'update', 'admin@example.com', 'api',
            json.dumps({'name': 'old', 'is_system': False}),
            json.dumps({'name': 'new', 'is_system': True}),
            None, None, 'success', None, _dt('2026-08-15T10:00:00'))
        event = serialize_audit_event(row)
        self.assertEqual(event['event_id'], 'audit-7')
        self.assertEqual(event['operation'], 'update')
        self.assertEqual(event['object_type'], 'tag')
        self.assertEqual(event['user'], 'admin@example.com')
        self.assertEqual(event['source'], 'api')
        self.assertEqual(event['before'], {'name': 'old', 'is_system': False})
        self.assertEqual(event['after'], {'name': 'new', 'is_system': True})
        self.assertIsNone(event['failure_reason'])


class AuditMergeTests(TestCase):

    def test_merge_and_paginate_sorts_across_sources(self):
        activity = [(1, 'create', 'file', 'u', _dt('2026-08-15T10:00:00'),
                     'repo', 'c', '/a', '{}')]
        audit = [(2, 'repo', 'tag', '1', 'create', 'u', 'api',
                  None, '{"name":"t"}', None, None, 'success', None,
                  _dt('2026-08-15T11:00:00'))]
        spec = parse_filters({'page': '1', 'per_page': '10'})
        result = merge_and_paginate(activity, audit, spec)
        self.assertEqual(result['total'], 2)
        # tag event is newer -> first
        self.assertEqual(result['events'][0]['event_id'], 'audit-2')
        self.assertEqual(result['events'][1]['event_id'], 'activity-1')

    def test_merge_and_paginate_pages(self):
        activity = []
        audit = []
        for i in range(5):
            audit.append((i + 1, 'repo', 'tag', str(i), 'create', 'u', 'api',
                          None, '{}', None, None, 'success', None,
                          _dt('2026-08-15T10:00:%02d' % i)))
        spec = parse_filters({'page': '2', 'per_page': '2'})
        result = merge_and_paginate(activity, audit, spec)
        self.assertEqual(result['total'], 5)
        self.assertEqual([e['event_id'] for e in result['events']],
                         ['audit-3', 'audit-2'])


class TagSnapshotTests(TestCase):

    class _Tag(object):
        def __init__(self):
            self.pk = 9
            self.repo_id = 'repo'
            self.name = 'system-tag'
            self.color = '#ff0000'
            self.is_system = True

    def test_tag_snapshot_includes_system_classification(self):
        snap = tag_snapshot(self._Tag())
        self.assertEqual(snap, {
            'repo_tag_id': 9, 'repo_id': 'repo', 'name': 'system-tag',
            'color': '#ff0000', 'is_system': True,
        })
