# -*- coding: utf-8 -*-
"""Managed library share planning: the rules that decide who loses access.

Decision source: eap-cloudfile docs/review/cloudfile_decision_20260827.md §4.4.
The cases worth having are the damage paths: an unmapped external id, a share
the ledger does not own, a duplicate desired entry, a revoked row that must
not come back by accident. Wrong answers here delete somebody's access or
hand a library to the wrong group, so they are tested as data, without a
server.
"""

from cloudfile_ext.sso.library_share_policy import DesiredShare, build


def ledger(ext, gid, perm, state='ACTIVE'):
    return {'seafile_group_id': gid, 'permission': perm, 'state': state,
            'last_error': ''}


# -- adding ----------------------------------------------------------------

def test_missing_share_is_added():
    plan = build([DesiredShare('dept-rd', 'rw')], {}, {'dept-rd': 7})

    assert plan.add == [(7, 'dept-rd', 'rw')]
    assert not plan.update and not plan.revoke and not plan.errors


def test_revoked_row_is_re_added_when_desired_again():
    """Re-granting after a revoke is a legitimate lifecycle, not an error."""
    plan = build([DesiredShare('dept-rd', 'r')],
                 {'dept-rd': ledger('dept-rd', 7, 'rw', state='REVOKED')},
                 {'dept-rd': 7})

    assert plan.add == [(7, 'dept-rd', 'r')]


# -- updating --------------------------------------------------------------

def test_permission_drift_is_updated_in_place():
    plan = build([DesiredShare('dept-rd', 'r')],
                 {'dept-rd': ledger('dept-rd', 7, 'rw')}, {'dept-rd': 7})

    assert plan.update == [(7, 'dept-rd', 'r')]
    assert not plan.add and not plan.revoke


def test_matching_state_produces_no_operations():
    plan = build([DesiredShare('dept-rd', 'rw')],
                 {'dept-rd': ledger('dept-rd', 7, 'rw')}, {'dept-rd': 7})

    assert not plan.add and not plan.update and not plan.revoke
    assert not plan.errors


# -- revoking --------------------------------------------------------------

def test_removed_desired_entry_revokes_ledgered_share():
    plan = build([], {'dept-rd': ledger('dept-rd', 7, 'rw')}, {})

    assert plan.revoke == [(7, 'dept-rd')]


def test_revoked_rows_are_not_revoked_twice():
    plan = build([], {'dept-rd': ledger('dept-rd', 7, 'rw', state='REVOKED')},
                 {'dept-rd': 7})

    assert not plan.revoke


def test_revoke_uses_the_live_group_map_over_the_stale_ledger_id():
    """A group recreated under a new id heals: revocation must hit the group
    the map points at now, not the dead id the ledger recorded."""
    plan = build([], {'dept-rd': ledger('dept-rd', 7, 'rw')},
                 {'dept-rd': 42})

    assert plan.revoke == [(42, 'dept-rd')]


# -- guards ----------------------------------------------------------------

def test_unmapped_external_id_is_an_error_not_a_guess():
    """No name matching, no group creation: the entry errors and the share,
    if any, stays as it was."""
    plan = build([DesiredShare('ghost', 'rw')],
                 {'ghost': ledger('ghost', 7, 'rw')}, {})

    assert not plan.add and not plan.update
    assert ('ghost', 'external id not mapped to a group') in plan.errors


def test_invalid_permission_is_rejected_whole():
    plan = build([DesiredShare('dept-rd', 'admin')], {}, {'dept-rd': 7})

    assert not plan.add
    assert ('dept-rd', "invalid permission 'admin'") in plan.errors


def test_duplicate_desired_entry_is_an_error():
    plan = build([DesiredShare('dept-rd', 'r'),
                  DesiredShare('dept-rd', 'rw')], {}, {'dept-rd': 7})

    assert not plan.add and not plan.update
    assert ('dept-rd', 'duplicated in desired') in plan.errors


def test_unresolvable_revoke_is_an_error_not_a_silent_keep():
    """Desired removed + group gone from the map + ledger id stale: keeping
    the share quietly is the worse outcome, so it must surface."""
    plan = build([], {'dept-rd': {'seafile_group_id': None,
                                  'permission': 'rw', 'state': 'ACTIVE',
                                  'last_error': ''}}, {})

    assert not plan.revoke
    assert ('dept-rd', 'cannot revoke: group no longer resolvable') \
        in plan.errors


def test_hand_made_share_is_invisible_to_the_plan():
    """The core property: a share in Seafile without a ledger row is not in
    the ledger input at all, so no plan the builder can produce touches it.
    This case documents the invariant the ledger exists to guarantee."""
    plan = build([DesiredShare('dept-rd', 'rw')], {}, {'dept-rd': 7,
                                                       'other': 9})

    # 'other' exists in the directory map but has no ledger row and is not
    # desired: nothing about it appears anywhere in the plan.
    assert plan.add == [(7, 'dept-rd', 'rw')]
    assert all('other' not in str(op) for op in plan.revoke)
