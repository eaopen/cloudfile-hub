# -*- coding: utf-8 -*-
"""Authorisation granularity policy + the probes' pure parts.

Django-free (the acl package imports Django only inside register()), so the
shared pytest-only checks can run the whole matrix.
"""

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
    assert 'dedicated folder' in message
    assert 'share link' in message


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
    assert 'no permission on the library' in message


def test_ineligible_group_gets_group_specific_message():
    message = granularity.check_eligibility(False, resolver.SUBJECT_GROUP)
    assert 'share on the library' in message


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
    assert 'dedicated folder' in item['guidance']


def test_annotate_marks_ineligible_rule():
    item = granularity.annotate(_rule(path='/docs'), granularity.KIND_DIR, False)
    assert item['path_kind'] == 'dir'
    assert item['eligible'] is False
    assert 'never take effect' in item['guidance']


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
