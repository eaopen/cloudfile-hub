"""No actual CE writes: UID/employee deltas and removal fail-closed rules."""
import pytest
from cloudfile_ext.sso.incremental import plan_uid_delta, IncrementalRefused


def example(status='active'):
    return {'userId': 'uid-1', 'status': status,
            'organizations': [{'namespace': 'directory', 'external_id': 'dept-27'}],
            'roles': [{'namespace': 'role', 'external_id': 'role-42'}]}


MAPPED = {'dept-27': {'group_id': 41}, 'role:role-42': {'group_id': 91},
          'dept-other': {'group_id': 95}}


def test_only_changed_direct_groups_are_planned():
    plan = plan_uid_delta(example(), MAPPED, {41, 95}, max_removals=1)
    assert plan == {'add': [91], 'remove': [95]}


def test_disabled_subject_revokes_only_mapped_groups_when_guard_allows():
    plan = plan_uid_delta(example('disabled'), MAPPED, {41, 95}, max_removals=2)
    assert plan == {'add': [], 'remove': [41, 95]}


def test_missing_external_group_never_causes_a_revoke():
    with pytest.raises(IncrementalRefused, match='group mapping'):
        plan_uid_delta(example(), {'dept-other': {'group_id': 95}}, {95}, max_removals=10)


def test_default_removal_guard_prevents_revoke():
    with pytest.raises(IncrementalRefused, match='permitted removals'):
        plan_uid_delta(example(), MAPPED, {41, 95})


def test_native_integer_collision_is_rejected():
    with pytest.raises(IncrementalRefused, match='native group mapping'):
        plan_uid_delta(example(), {'dept-27': {'group_id': 41}, 'role:role-42': {'group_id': 41}}, {41})


def test_wrong_group_namespace_refused():
    bad = example()
    bad['roles'] = [{'namespace': 'directory', 'external_id': 'role-42'}]
    with pytest.raises(IncrementalRefused, match='role'):
        plan_uid_delta(bad, MAPPED, set())


def test_empty_context_is_not_an_authoritative_removal():
    with pytest.raises(IncrementalRefused):
        plan_uid_delta({'status': 'active', 'organizations': []}, MAPPED, set())
