# -*- coding: utf-8 -*-
"""Pure audit-query contract, kept independent of Django for unit tests."""

VALID_OPS = frozenset(('create', 'edit', 'delete', 'rename', 'move', 'recover'))
VALID_OBJECTS = frozenset(('file', 'dir'))


def filters(params):
    clauses, values = [], []
    repo_id = params.get('repo_id', '').strip()
    user = params.get('user', '').strip()
    op_type = params.get('op_type', '').strip()
    obj_type = params.get('obj_type', '').strip()
    if repo_id:
        clauses.append('repo_id = %s')
        values.append(repo_id)
    if user:
        clauses.append('op_user = %s')
        values.append(user)
    if op_type:
        if op_type not in VALID_OPS:
            raise ValueError('op_type invalid.')
        clauses.append('op_type = %s')
        values.append(op_type)
    if obj_type:
        if obj_type not in VALID_OBJECTS:
            raise ValueError('obj_type invalid.')
        clauses.append('obj_type = %s')
        values.append(obj_type)
    return clauses, values
