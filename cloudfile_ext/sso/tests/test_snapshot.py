# -*- coding: utf-8 -*-
"""The hierarchical directory contract: validation and create ordering.

Decision source: eap-cloudfile docs/review/cloudfile_decision_20260827.md §3.
Every case below is a way a directory could describe something Seafile cannot
represent, or that the ACL walker would misread once written -- a cycle, a
missing parent, a duplicate id, a group with a parent. All of them must be
refused whole, before anything is planned, so the last good state survives.

Django-free, like the rest of cloudfile_ext's tests.
"""

import pytest

from cloudfile_ext.sso import reconcile, snapshot


def entry(external_id, name=None, members=(), **extra):
    base = {'external_id': external_id, 'name': name or external_id,
            'members': list(members)}
    base.update(extra)
    return base


# -- validation ------------------------------------------------------------

def test_flat_snapshot_without_hierarchy_fields_is_valid():
    """Old-shape feeds keep working unchanged (decision §3.2 compat stage)."""
    validated = snapshot.validate([
        entry('eng', 'Engineering', ['a']),
    ])

    assert validated == [{'external_id': 'eng', 'name': 'Engineering',
                          'members': ['a'],
                          'subject_type': 'group',
                          'parent_external_id': None}]


def test_dept_with_parent_is_valid():
    validated = snapshot.validate([
        entry('root', '总部', [], subject_type='dept'),
        entry('rd', '研发部', ['alice'], subject_type='dept',
              parent_external_id='root'),
    ])

    assert {e['external_id']: e['subject_type'] for e in validated} == {
        'root': 'dept', 'rd': 'dept'}


def test_duplicate_external_id_is_rejected():
    with pytest.raises(snapshot.SnapshotRejected, match='duplicate'):
        snapshot.validate([entry('eng'), entry('eng', 'Other')])


def test_missing_external_id_is_rejected():
    with pytest.raises(snapshot.SnapshotRejected, match='without external_id'):
        snapshot.validate([entry('', 'Engineering')])


def test_unknown_subject_type_is_rejected():
    with pytest.raises(snapshot.SnapshotRejected, match='subject_type'):
        snapshot.validate([entry('eng', subject_type='team')])


def test_group_with_parent_is_rejected():
    """Hierarchy is dept-only; a parent on a group is a contract mistake."""
    with pytest.raises(snapshot.SnapshotRejected, match='dept-only'):
        snapshot.validate([
            entry('root', subject_type='dept'),
            entry('role', parent_external_id='root'),
        ])


def test_parent_outside_snapshot_is_rejected():
    """A parent the feed does not carry cannot be keyed by external id.

    Matching it by name is what decision §3.1 forbids.
    """
    with pytest.raises(snapshot.SnapshotRejected, match='does not name a dept'):
        snapshot.validate([
            entry('rd', subject_type='dept', parent_external_id='ghost'),
        ])


def test_parent_that_is_a_group_is_rejected():
    with pytest.raises(snapshot.SnapshotRejected, match='does not name a dept'):
        snapshot.validate([
            entry('role', subject_type='group'),
            entry('rd', subject_type='dept', parent_external_id='role'),
        ])


def test_dept_cycle_is_rejected():
    with pytest.raises(snapshot.SnapshotRejected, match='cycle'):
        snapshot.validate([
            entry('a', subject_type='dept', parent_external_id='b'),
            entry('b', subject_type='dept', parent_external_id='a'),
        ])


def test_self_parent_cycle_is_rejected():
    with pytest.raises(snapshot.SnapshotRejected, match='cycle'):
        snapshot.validate([
            entry('a', subject_type='dept', parent_external_id='a'),
        ])


def test_non_list_snapshot_is_rejected():
    with pytest.raises(snapshot.SnapshotRejected, match='list'):
        snapshot.validate({'groups': []})


# -- revision --------------------------------------------------------------

def test_revision_of_wrapped_payload():
    assert snapshot.revision_of(
        {'revision': 'org-1', 'groups': []}) == 'org-1'


def test_revision_of_absent_is_none():
    assert snapshot.revision_of({'groups': []}) is None
    assert snapshot.revision_of([entry('eng')]) is None


def test_blank_revision_is_none():
    assert snapshot.revision_of({'revision': '  ', 'groups': []}) is None


# -- create ordering -------------------------------------------------------

def test_depts_are_created_parents_before_children():
    """The apply layer resolves a sub-dept's parent from rows it just wrote,
    so a child must never precede its parent in plan.create."""
    snap = snapshot.validate([
        entry('leaf', subject_type='dept', parent_external_id='mid'),
        entry('root', subject_type='dept'),
        entry('mid', subject_type='dept', parent_external_id='root'),
        entry('role', subject_type='group'),
    ])

    plan = reconcile.build(snap, {}, {})

    order = [c['external_id'] for c in plan.create]
    assert order.index('root') < order.index('mid') < order.index('leaf')


def test_create_entries_carry_hierarchy_fields():
    snap = snapshot.validate([
        entry('root', subject_type='dept'),
        entry('rd', subject_type='dept', parent_external_id='root',
              members=['alice']),
    ])

    plan = reconcile.build(snap, {}, {})

    creates = {c['external_id']: c for c in plan.create}
    assert creates['root']['parent_external_id'] is None
    assert creates['rd']['parent_external_id'] == 'root'
    assert creates['rd']['subject_type'] == 'dept'
    assert creates['rd']['members'] == ['alice']


def test_snapshot_position_of_flat_groups_is_preserved():
    """Groups carry no ordering constraint; reordering them would only churn
    the dry-run diff an operator compares between ticks."""
    snap = snapshot.validate([
        entry('z-group', subject_type='group'),
        entry('root', subject_type='dept'),
        entry('a-group', subject_type='group'),
    ])

    plan = reconcile.build(snap, {}, {})

    assert [c['external_id'] for c in plan.create] == [
        'z-group', 'root', 'a-group']


def test_member_user_ids_contract_v2_wins():
    """Contract v2 (decision 2026-08-28 §2.3): enterprise userIds replace
    login strings; when both keys appear the v2 key wins."""
    raw = {'external_id': 'dept-a', 'name': 'A',
           'members': ['alice@example.com'],
           'member_user_ids': ['1001', '1002']}
    entry = snapshot.normalize_entry(raw)
    assert entry['members'] == ['1001', '1002']
    snapshot.validate([entry])


def test_members_still_valid_for_unupgraded_providers():
    raw = {'external_id': 'g', 'name': 'G', 'members': ['a@e.com']}
    entry = snapshot.normalize_entry(raw)
    assert entry['members'] == ['a@e.com']

def test_member_accounts_pass_through():
    """Contract v2.1: member_accounts (login emails) rides along untouched;
    the identity layer, not the validator, decides what they mean."""
    raw = {'external_id': 'dept-a', 'name': 'A',
           'member_user_ids': ['1001'],
           'member_accounts': ['admin@shanghai-electric.com',
                                'zhangsan@shanghai-electric.com']}
    entry = snapshot.normalize_entry(raw)
    assert entry['members'] == ['1001']
    assert entry['member_accounts'] == ['admin@shanghai-electric.com',
                                         'zhangsan@shanghai-electric.com']
    snapshot.validate([entry])

def test_member_accounts_absent_is_none():
    raw = {'external_id': 'g', 'name': 'G', 'members': ['a@e.com']}
    entry = snapshot.normalize_entry(raw)
    assert entry['member_accounts'] is None
