"""Indexed desired-share plan; no file or directory inventory lookup."""

def plan(cursor, repo_id, provider, desired):
    cursor.execute('SELECT external_id,group_id,permission,state FROM cf_library_share_ledger WHERE repo_id=%s', (repo_id,))
    ledger = {row[0]: row[1:] for row in cursor.fetchall()}
    if any(type(row[0]) is not int or row[0] <= 0 or row[1] not in ('r', 'rw')
           or row[2] not in ('APPLIED', 'REVOKED', 'PENDING') for row in ledger.values()):
        raise ValueError('Invalid managed library share ledger')
    resolved = {}
    errors = []
    for external_id in desired:
        # eTech's role: prefix distinguishes its flat roles from department IDs.
        # All four columns use group_map_subject; this does not scan file rows.
        is_role = external_id.startswith('role:')
        kind, namespace = ('group', 'role') if is_role else ('dept', 'directory')
        mapped_id = external_id[5:] if is_role else external_id
        cursor.execute("SELECT group_id FROM cf_sso_group_map WHERE provider=%s AND subject_type=%s AND namespace=%s AND external_id=%s",
                       (provider, kind, namespace, mapped_id))
        groups = cursor.fetchall()
        if len(groups) != 1 or type(groups[0][0]) is not int or groups[0][0] <= 0:
            errors.append(external_id + ': group mapping is missing or ambiguous')
        else:
            resolved[external_id] = groups[0][0]
    plan = {'add': [], 'update': [], 'revoke': []}
    for external_id, permission in desired.items():
        if external_id not in resolved:
            continue
        row = ledger.get(external_id)
        if row is None or row[2] != 'APPLIED':
            plan['add'].append((external_id, resolved[external_id], permission))
        elif row[0] != resolved[external_id]:
            errors.append(external_id + ': native group mapping changed; manual reconciliation required')
        elif row[1] != permission:
            plan['update'].append((external_id, resolved[external_id], permission))
    for external_id, (group_id, _, state) in ledger.items():
        if state in ('APPLIED', 'PENDING') and external_id not in desired:
            plan['revoke'].append((external_id, group_id, None))
    return plan, errors
