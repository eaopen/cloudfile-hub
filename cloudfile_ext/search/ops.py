# -*- coding: utf-8 -*-
"""Pure helpers for the meilisearch indexer (P2-09).

Kept free of Django/seafile imports so the batch-op semantics stay
unit-testable on their own (the convention: pure algorithm code must not pull
in Django).
"""

import hashlib


def normalize_op(op_type):
    """seafevents merges consecutive commits into batch_<op> Activity rows."""
    if op_type.startswith('batch_'):
        return op_type[len('batch_'):]
    return op_type


def doc_id(repo_id, path):
    """Stable Meilisearch document id for (repo_id, path)."""
    return '%s:%s' % (repo_id, hashlib.sha1(path.encode('utf-8')).hexdigest())
