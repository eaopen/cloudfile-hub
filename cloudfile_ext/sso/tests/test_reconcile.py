# -*- coding: utf-8 -*-
"""What a directory sync is and is not allowed to decide.

There is no second implementation to keep in step here, so unlike the ACL
resolver these cases live as tests rather than as a shared JSON case set --
a case file that only one implementation reads is bookkeeping, not a contract.

The cases worth having are the ones about damage: a feed that comes back empty,
a feed that comes back truncated, a group an administrator made by hand. Those
are the paths where being wrong costs someone their access, and the last one is
the reason `mapped` exists at all.

Django-free, like the rest of cloudfile_ext's tests: the shared checks install
pytest and nothing else.
"""

import pytest

from cloudfile_ext.sso import reconcile


def group(external_id, name=None, members=()):
    return {'external_id': external_id, 'name': name or external_id,
            'members': list(members)}


# -- creating and mapping --------------------------------------------------

def test_unmapped_directory_group_is_created_with_its_members():
    plan = reconcile.build([group('eng', 'Engineering', ['a', 'b'])], {}, {})

    assert plan.create == [{'external_id': 'eng', 'name': 'Engineering',
                            'members': ['a', 'b'],
                            'subject_type': 'group',
                            'parent_external_id': None}]
    assert not plan.add          # membership rides along with the creation
    assert not plan.remove


def test_group_without_external_id_is_refused():
    """Names are not identities.

    Matching on the display name instead would re-create every group the first
    time the directory renames one, orphaning the libraries shared into the
    old one.
    """
    with pytest.raises(reconcile.SyncRefused):
        reconcile.build([group('', 'Engineering')], {}, {})


def test_rename_follows_the_directory():
    mapped = {'eng': {'group_id': 7, 'name': 'Engineering'}}
    plan = reconcile.build([group('eng', 'Platform', ['a'])], mapped, {7: ['a']})

    assert plan.rename == [{'group_id': 7, 'name': 'Platform'}]


def test_unchanged_state_produces_an_empty_plan():
    mapped = {'eng': {'group_id': 7, 'name': 'Engineering'}}
    plan = reconcile.build([group('eng', 'Engineering', ['a', 'b'])],
                           mapped, {7: ['b', 'a']})

    assert plan.empty, plan.counts()


# -- membership ------------------------------------------------------------

def test_membership_mirrors_the_directory_in_both_directions():
    mapped = {'eng': {'group_id': 7, 'name': 'Engineering'}}
    plan = reconcile.build([group('eng', 'Engineering', ['a', 'c'])],
                           mapped, {7: ['a', 'b']})

    assert plan.add == [{'group_id': 7, 'identity': 'c'}]
    assert plan.remove == [{'group_id': 7, 'identity': 'b'}]


def test_case_and_whitespace_are_not_membership_changes():
    """Otherwise the same person is removed and re-added on every tick."""
    mapped = {'eng': {'group_id': 7, 'name': 'Engineering'}}
    plan = reconcile.build([group('eng', 'Engineering', [' Alice@Example.com '])],
                           mapped, {7: ['alice@example.com']})

    assert plan.empty, plan.counts()


def test_protected_members_are_never_removed():
    """The group's creator is not in the directory and must stay anyway.

    Seafile groups need an owner. Without this the first tick removes the
    service account from every group it just created, and the second tick
    cannot manage them any more.
    """
    mapped = {'eng': {'group_id': 7, 'name': 'Engineering'}}
    plan = reconcile.build([group('eng', 'Engineering', ['a'])],
                           mapped, {7: ['a', 'sso@service']},
                           protected={7: ['sso@service']})

    assert not plan.remove


# -- what it must not touch ------------------------------------------------

def test_unmapped_groups_are_invisible_to_the_sync():
    """A group CloudFile did not create is not in `mapped`, so nothing in the
    plan can name it -- there is no code path that reaches one."""
    mapped = {'eng': {'group_id': 7, 'name': 'Engineering'}}
    members = {7: ['a'], 99: ['someone-elses-group-member']}

    plan = reconcile.build([group('eng', 'Engineering', ['a'])], mapped, members)

    touched = {entry['group_id'] for entry in plan.add + plan.remove}
    touched |= {entry['group_id'] for entry in plan.rename}
    assert 99 not in touched


def test_a_group_that_left_the_directory_is_unmapped_not_deleted():
    """It may own libraries. Stopping the sync is reversible; deleting is not."""
    mapped = {'eng': {'group_id': 7, 'name': 'Engineering'},
              'sales': {'group_id': 8, 'name': 'Sales'}}
    plan = reconcile.build([group('eng', 'Engineering', ['a'])],
                           mapped, {7: ['a'], 8: ['b']})

    assert plan.unmap == [{'external_id': 'sales', 'group_id': 8}]
    # ...and in particular its members are left alone, rather than removed on
    # the way out.
    assert not plan.remove


# -- the guards ------------------------------------------------------------

def test_empty_snapshot_against_mapped_groups_is_refused():
    """An expired token and a genuinely empty directory look identical here.

    Applying the literal reading empties every mapped group, in one tick, with
    a 200 in the log.
    """
    mapped = {'eng': {'group_id': 7, 'name': 'Engineering'}}

    with pytest.raises(reconcile.SyncRefused) as exc:
        reconcile.build([], mapped, {7: ['a', 'b']})

    assert 'refusing' in str(exc.value)


def test_empty_snapshot_is_fine_when_nothing_is_mapped_yet():
    """First run against a directory with no groups: nothing to lose."""
    assert reconcile.build([], {}, {}).empty


def test_a_plan_that_removes_too_much_is_refused_whole():
    mapped = {'eng': {'group_id': 7, 'name': 'Engineering'}}
    members = {7: ['a', 'b', 'c', 'd']}

    with pytest.raises(reconcile.SyncRefused) as exc:
        reconcile.build([group('eng', 'Engineering', ['a'])], mapped, members)

    assert '3 of 4' in str(exc.value)


def test_the_removal_limit_is_a_setting_not_a_law():
    """A real reorganisation has to be applyable, once someone has looked."""
    mapped = {'eng': {'group_id': 7, 'name': 'Engineering'}}
    members = {7: ['a', 'b', 'c', 'd']}

    plan = reconcile.build([group('eng', 'Engineering', ['a'])], mapped,
                           members, max_removal_ratio=None)

    assert len(plan.remove) == 3


def test_the_limit_is_measured_against_managed_members_only():
    """Groups CloudFile does not manage must not dilute the ratio.

    Counting them would let a large hand-made group raise the ceiling until
    the guard stops firing on the groups it is there to protect.
    """
    mapped = {'eng': {'group_id': 7, 'name': 'Engineering'}}
    # 99 is not mapped, so build() never reads it -- passing it here documents
    # that the ratio is computed from `members`, which the caller populates
    # from mapped groups alone.
    members = {7: ['a', 'b']}

    with pytest.raises(reconcile.SyncRefused):
        reconcile.build([group('eng', 'Engineering', [])], mapped, members)
