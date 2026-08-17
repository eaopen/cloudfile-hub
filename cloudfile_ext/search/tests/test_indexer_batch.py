# -*- coding: utf-8 -*-
"""Pure tests for the meilisearch indexer's batch-event handling (P2-09).

seafevents merges consecutive commits of one operation into a single Activity
row whose op_type is `batch_<op>` and whose detail is a list of the individual
items. The indexer must normalize the op and expand the detail list, or every
upload (which arrives as `batch_create`) is silently skipped.
"""

import json

from cloudfile_ext.search.ops import normalize_op as _normalize_op, doc_id as _doc_id


def test_batch_op_normalization():
    assert _normalize_op('batch_create') == 'create'
    assert _normalize_op('batch_edit') == 'edit'
    assert _normalize_op('batch_delete') == 'delete'
    assert _normalize_op('batch_move') == 'move'
    assert _normalize_op('batch_rename') == 'rename'
    assert _normalize_op('batch_recover') == 'recover'


def test_non_batch_op_passes_through():
    assert _normalize_op('create') == 'create'
    assert _normalize_op('delete') == 'delete'


def test_doc_id_is_stable_per_repo_path():
    assert _doc_id('r1', '/a.txt') == _doc_id('r1', '/a.txt')
    assert _doc_id('r1', '/a.txt') != _doc_id('r2', '/a.txt')
    assert _doc_id('r1', '/a.txt') != _doc_id('r1', '/b.txt')


def test_batch_detail_is_a_json_list_of_items():
    # The shape seafevents writes for a merged batch_create row.
    detail = json.dumps([
        {'obj_id': 'x' * 40, 'path': '/alpha.txt', 'size': 5},
        {'obj_id': 'y' * 40, 'path': '/nested.txt', 'size': 6},
    ])
    parsed = json.loads(detail)
    assert isinstance(parsed, list)
    assert [it['path'] for it in parsed] == ['/alpha.txt', '/nested.txt']
