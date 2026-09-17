# -*- coding: utf-8 -*-
"""Authorisation granularity policy + the probes' pure parts.

Django-free (the acl package imports Django only inside register()), so the
shared pytest-only checks can run the whole matrix.
"""

import sys

import pytest

from cloudfile_ext.acl import granularity, probes, resolver


# -- check_grant: folder is the granting granularity -------------------------

@pytest.mark.parametrize('permission', ['r', 'rw'])
@pytest.mark.parametrize('kind', [granularity.KIND_ROOT, granularity.KIND_DIR])
def test_grant_allowed_on_root_and_dirs(kind, permission):
    assert granularity.check_grant(kind, permission) is None


@pytest.mark.parametrize('permission', ['r', 'rw'])
def test_grant_on_file_is_refused_with_guidance(permission):
    message = granularity.check_grant(granularity.KIND_FILE, permission)
    assert message
    # The guidance has to name both ways out, otherwise the admin is stuck.
    # The wording is Chinese: it is shown verbatim to operators (2026-09-16).
    assert '专属目录' in message
    assert '分享链接' in message


@pytest.mark.parametrize('permission', list(resolver.DENYING))
@pytest.mark.parametrize('kind', [granularity.KIND_ROOT, granularity.KIND_DIR,
                                  granularity.KIND_FILE])
def test_deny_allowed_at_any_depth(kind, permission):
    # Denies veto at every entry point and the read paths evaluate them per
    # object, so hiding one file stays legitimate.
    assert granularity.check_grant(kind, permission) is None


# -- check_eligibility -------------------------------------------------------

def test_ineligible_user_is_refused():
    message = granularity.check_eligibility(False, resolver.SUBJECT_USER)
    assert '没有任何权限' in message
    # A user-level message must not be the group one.
    assert granularity.INELIGIBLE_GROUP_MESSAGE not in message


def test_ineligible_group_gets_group_specific_message():
    message = granularity.check_eligibility(False, resolver.SUBJECT_GROUP)
    assert '未被分享本库' in message
    assert message != granularity.INELIGIBLE_MESSAGE


def test_unknown_eligibility_must_not_block_a_write():
    # A failed probe is not a reason to lock an administrator out.
    assert granularity.check_eligibility(None, resolver.SUBJECT_USER) is None


def test_eligible_subject_passes():
    assert granularity.check_eligibility(True, resolver.SUBJECT_USER) is None


# -- annotate: what makes the silent class visible ---------------------------

def _rule(**over):
    rule = {'subject_type': resolver.SUBJECT_USER, 'subject': 'x',
            'permission': 'rw', 'path': '/a.xlsx'}
    rule.update(over)
    return rule


def test_annotate_marks_file_grant_with_guidance():
    item = granularity.annotate(_rule(), granularity.KIND_FILE, True)
    assert item['path_kind'] == 'file'
    assert item['eligible'] is True
    assert '专属目录' in item['guidance']


def test_annotate_marks_ineligible_rule():
    item = granularity.annotate(_rule(path='/docs'), granularity.KIND_DIR, False)
    assert item['path_kind'] == 'dir'
    assert item['eligible'] is False
    assert '永远不会生效' in item['guidance']


def test_annotate_keeps_rule_fields():
    item = granularity.annotate(_rule(), granularity.KIND_DIR, True)
    assert item['permission'] == 'rw'
    assert item['path'] == '/a.xlsx'


# -- probes: pure parts ------------------------------------------------------

def test_path_kind_classifies_root_dir_file():
    file_probe = lambda repo, path: 'fid' if path.endswith('.xlsx') else None
    dir_probe = lambda repo, path: 'did' if path != '/' else None
    assert probes.path_kind('r', '/', file_probe, dir_probe) == 'root'
    assert probes.path_kind('r', '/a.xlsx', file_probe, dir_probe) == 'file'
    assert probes.path_kind('r', '/docs', file_probe, dir_probe) == 'dir'


def test_path_kind_falls_back_to_dir_when_probes_fail():
    def boom(repo, path):
        raise RuntimeError('rpc down')
    # Never claim "file" (which would refuse grants) on a failed probe.
    assert probes.path_kind('r', '/docs', boom, boom) == 'dir'


class FakeGroup(object):
    def __init__(self, parent):
        self.parent_group_id = parent


def test_dept_ancestors_walk_up_the_chain():
    groups = {583: FakeGroup(2), 2: FakeGroup(1), 1: FakeGroup(-1)}
    assert probes.dept_ancestor_ids(583, groups.get) == [583, 2, 1]


def test_dept_ancestors_survive_cycles_and_bad_ids():
    groups = {5: FakeGroup(5)}
    assert probes.dept_ancestor_ids(5, groups.get) == [5]
    assert probes.dept_ancestor_ids('not-a-number', groups.get) == []


def test_subject_eligible_uses_injected_probes():
    assert probes.subject_eligible(
        'r', 'user', 'u', {'user_permission': lambda repo, user: 'rw'}) is True
    assert probes.subject_eligible(
        'r', 'user', 'u', {'user_permission': lambda repo, user: None}) is False
    assert probes.subject_eligible(
        'r', 'group', '1', {'group_shared': lambda repo, group: True}) is True


def test_subject_eligible_returns_unknown_on_probe_failure():
    def boom(*args):
        raise RuntimeError('rpc down')
    assert probes.subject_eligible('r', 'user', 'u', {'user_permission': boom}) is None


# -- _group_shared: RepoGroup is gone from seahub.share.models on Seafile 14 --
#
# Regression guard. The old implementation opened with
# ``from seahub.share.models import RepoGroup``; Seafile 14 deleted that model
# (only the table remains, read through ``db_api.SeafileDB``), so the import
# raised, ``subject_eligible``'s broad ``except`` swallowed it, and *every*
# department/group probe answered "unknown" -- which silently disabled both the
# write-time eligibility check and the report's warning annotation.

# What the raw-SQL reader returns for the library the bug was found on
# (share-info reported shared_group_ids == [1]).
SHARED_GROUP_ROWS = [{'share_type': 'group', 'repo_id': 'r', 'path': '/',
                      'share_from': 'admin', 'share_to': 1, 'permission': 'rw'}]


def _share_lister(rows):
    return lambda repo_id, org_id: rows


def test_group_shared_matches_a_direct_share(monkeypatch):
    monkeypatch.setattr(probes, 'dept_ancestor_ids', lambda gid: [int(gid)])
    assert probes._group_shared(
        'r', '1', _share_lister(SHARED_GROUP_ROWS), org_id='') is True


def test_group_shared_false_when_no_ancestor_is_shared(monkeypatch):
    # dept 583 and its parents are not shared: the rule can never take effect,
    # which is a real finding the report has to be able to state.
    # The subject is spelled out as a department (parent_group_id != 0) because
    # only departments keep the chain-based verdict; a role gets a member scan
    # instead (see the 2026-09-17 guard below).
    monkeypatch.setattr(probes, 'dept_ancestor_ids', lambda gid: [int(gid)])
    monkeypatch.setattr(probes, 'parent_group_id_of', lambda gid: 2)
    assert probes._group_shared(
        'r', '583', _share_lister(SHARED_GROUP_ROWS), org_id='') is False


def test_group_shared_matches_a_parent_department(monkeypatch):
    # Membership is inherited, so a share with the parent makes 583 eligible.
    real = probes.dept_ancestor_ids
    groups = {583: 1, 1: 0}
    monkeypatch.setattr(
        probes, 'dept_ancestor_ids',
        lambda gid: real(gid, lambda g: FakeGroup(groups[g])))
    assert probes._group_shared(
        'r', '583', _share_lister(SHARED_GROUP_ROWS), org_id='') is True


def test_group_shared_unknown_when_subject_is_not_a_group_id(monkeypatch):
    monkeypatch.setattr(probes, 'dept_ancestor_ids', lambda gid: [])
    assert probes._group_shared(
        'r', 'not-a-number', _share_lister([]), org_id='') is None


def test_group_shared_probe_failure_stays_unknown(monkeypatch):
    # A failing share read must surface as None ("cannot tell"), never as False:
    # False would let the report declare valid rules dead -- and the batch
    # cleanup in the admin UI would delete them.
    monkeypatch.setattr(probes, 'dept_ancestor_ids', lambda gid: [1])

    def boom(repo_id, org_id):
        raise RuntimeError('db down')

    with pytest.raises(RuntimeError):
        probes._group_shared('r', '1', boom, org_id='')
    assert probes.subject_eligible(
        'r', 'group', '1', {'group_shared': boom}) is None


# -- _group_shared: a role is not an access axis of its own ------------------
#
# Regression guard (2026-09-17). A role / plain group (parent_group_id == 0) has
# no department above it, so its members reach a library through their own
# departments (a share on a parent department covers sub-department members) or
# through personal user shares -- neither of which a per-subject probe can see.
# Judging such a subject by its own share state alone declared working rules
# "never effective", and the admin UI's batch cleanup then deletes them.
# Departments keep the chain-based verdict: their department chain *is* the
# axis their members are reached through.

ORDINARY_GROUP = 0


def _never_called(name):
    def fn(*args, **kwargs):
        raise AssertionError('%s should not have been called' % name)
    return fn


def test_group_shared_role_scans_members_when_not_shared(monkeypatch):
    monkeypatch.setattr(probes, 'dept_ancestor_ids', lambda gid: [int(gid)])
    monkeypatch.setattr(probes, 'parent_group_id_of', lambda gid: ORDINARY_GROUP)
    seen = []

    def member_reaches(repo_id, group_id):
        seen.append((repo_id, group_id))
        return True

    monkeypatch.setattr(probes, '_member_reaches_library', member_reaches)
    assert probes._group_shared(
        'r', '1245', _share_lister([]), org_id='') is True
    assert seen == [('r', '1245')]


def test_group_shared_role_without_a_covered_member_is_false(monkeypatch):
    monkeypatch.setattr(probes, 'dept_ancestor_ids', lambda gid: [int(gid)])
    monkeypatch.setattr(probes, 'parent_group_id_of', lambda gid: ORDINARY_GROUP)
    monkeypatch.setattr(probes, '_member_reaches_library', lambda repo, gid: False)
    assert probes._group_shared(
        'r', '1245', _share_lister([]), org_id='') is False


def test_group_shared_role_member_scan_truncated_stays_unknown(monkeypatch):
    monkeypatch.setattr(probes, 'dept_ancestor_ids', lambda gid: [int(gid)])
    monkeypatch.setattr(probes, 'parent_group_id_of', lambda gid: ORDINARY_GROUP)
    monkeypatch.setattr(probes, '_member_reaches_library', lambda repo, gid: None)
    assert probes._group_shared(
        'r', '1245', _share_lister([]), org_id='') is None


def test_group_shared_role_shared_directly_skips_the_member_scan(monkeypatch):
    monkeypatch.setattr(probes, 'dept_ancestor_ids', lambda gid: [int(gid)])
    monkeypatch.setattr(probes, 'parent_group_id_of',
                        _never_called('parent_group_id_of'))
    monkeypatch.setattr(probes, '_member_reaches_library',
                        _never_called('the member scan'))
    assert probes._group_shared(
        'r', '1', _share_lister(SHARED_GROUP_ROWS), org_id='') is True


def test_group_shared_department_never_scans_members(monkeypatch):
    monkeypatch.setattr(probes, 'dept_ancestor_ids', lambda gid: [int(gid)])
    monkeypatch.setattr(probes, 'parent_group_id_of', lambda gid: 2)
    monkeypatch.setattr(probes, '_member_reaches_library',
                        _never_called('the member scan'))
    assert probes._group_shared(
        'r', '583', _share_lister([]), org_id='') is False


def test_group_shared_unknown_when_the_group_type_cannot_be_read(monkeypatch):
    # Without a readable parent_group_id a role cannot be told from a
    # department, so the answer has to be unknown -- never False.
    monkeypatch.setattr(probes, 'dept_ancestor_ids', lambda gid: [int(gid)])
    monkeypatch.setattr(probes, 'parent_group_id_of', lambda gid: None)
    monkeypatch.setattr(probes, '_member_reaches_library',
                        _never_called('the member scan'))
    assert probes._group_shared(
        'r', '1245', _share_lister([]), org_id='') is None


# -- parent_group_id_of ------------------------------------------------------


def test_parent_group_id_of_classifies_roles_and_departments():
    groups = {1245: FakeGroup(0), 583: FakeGroup(2), 1: FakeGroup(-1)}
    assert probes.parent_group_id_of(1245, groups.get) == 0
    assert probes.parent_group_id_of(583, groups.get) == 2
    assert probes.parent_group_id_of(1, groups.get) == -1


def test_parent_group_id_of_is_unknown_for_bad_or_missing_ids():
    groups = {1: FakeGroup(-1)}
    assert probes.parent_group_id_of('not-a-number', groups.get) is None
    assert probes.parent_group_id_of(999, groups.get) is None


# -- _member_reaches_library -------------------------------------------------


class FakeMember(object):
    def __init__(self, user_name):
        self.user_name = user_name


def _member_lister(user_names):
    def fn(group_id, start, limit=None):
        return [FakeMember(name) for name in user_names]
    return fn


def test_member_reaches_library_stops_at_the_first_covered_member():
    checked = []

    def user_permission(repo_id, username):
        checked.append(username)
        return 'rw' if username == 'b@x' else None

    assert probes._member_reaches_library(
        'r', '1245', _member_lister(['a@x', 'b@x', 'c@x']),
        user_permission) is True
    assert checked == ['a@x', 'b@x']


def test_member_reaches_library_false_only_after_checking_every_member():
    assert probes._member_reaches_library(
        'r', '1245', _member_lister(['a@x', 'b@x']),
        lambda repo, user: None) is False


def test_member_reaches_library_false_for_an_empty_group():
    assert probes._member_reaches_library(
        'r', '1245', _member_lister([]),
        _never_called('user_permission')) is False


def test_member_reaches_library_unknown_when_the_scan_hits_the_cap():
    # limit + 1 rows came back, so the list was truncated: a partial scan cannot
    # prove that no member is covered.
    assert probes._member_reaches_library(
        'r', '1245', _member_lister(['a@x', 'b@x', 'c@x']),
        lambda repo, user: None, limit=2) is None


def test_member_reaches_library_accepts_plain_string_members():
    def members(group_id, start, limit=None):
        return ['a@x']
    assert probes._member_reaches_library(
        'r', '1245', members, lambda repo, user: 'r') is True


def test_member_reaches_library_probe_failure_is_not_swallowed():
    # A failing per-member check must reach subject_eligible's handler and
    # degrade to unknown, never to a dead-rule verdict.
    def boom(repo_id, username):
        raise RuntimeError('rpc down')

    with pytest.raises(RuntimeError):
        probes._member_reaches_library('r', '1245', _member_lister(['a@x']), boom)


def test_repo_org_id_degrades_to_empty(monkeypatch):
    # No request context here, so the org has to come from the repo; when that
    # lookup is unavailable '' still reaches the common non-org table.
    monkeypatch.setitem(sys.modules, 'seaserv', None)
    assert probes._repo_org_id('r') == ''
