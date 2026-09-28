# -*- coding: utf-8 -*-
"""Run the shared ACL case set against the Python resolver.

The same docs/acl-cases.json drives the C and Go suites in cloudfile-server.
If a case fails here it must be fixed in the spec first, then in all three
implementations -- never in one of them alone.

The case file lives in the cloudfile-docker repo. Point CF_ACL_CASES at it, or
check the three repos out side by side and the default relative path works.
"""

import json
import os

import pytest

from cloudfile_ext.acl import resolver


def _cases_path():
    override = os.environ.get('CF_ACL_CASES')
    if override:
        return override
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.normpath(os.path.join(here, '..', '..', '..'))
    return os.path.join(os.path.dirname(repo_root),
                        'cloudfile-docker', 'docs', 'acl-cases.json')


def _load():
    path = _cases_path()
    if not os.path.exists(path):
        pytest.skip('shared ACL case set not found at %s; set CF_ACL_CASES'
                    % path)
    with open(path, encoding='utf-8') as fp:
        return json.load(fp)


def _flatten():
    data = _load()
    for case in data['cases']:
        for check in case['checks']:
            yield pytest.param(
                case, check,
                id='%s :: %s (native=%s)' % (
                    case['name'], check['path'] or '<empty>', check['native']),
            )


@pytest.mark.parametrize('case,check', list(_flatten()))
def test_shared_cases(case, check):
    subjects = resolver.subject_set(
        case['subjects']['user'],
        case['subjects'].get('groups', ()),
        case['subjects'].get('depts', ()),
    )
    got = resolver.resolve(
        case['rules'], subjects, check['path'], check['native'])
    assert got == check['expect']


def test_normalize_path():
    assert resolver.normalize_path('') == '/'
    assert resolver.normalize_path('/') == '/'
    assert resolver.normalize_path('a/b') == '/a/b'
    assert resolver.normalize_path('//a//b//') == '/a/b'


def test_ancestors():
    assert resolver.ancestors('/') == ['/']
    assert resolver.ancestors('/a/b') == ['/', '/a', '/a/b']


def test_denies_is_true_only_for_outright_denying_rules():
    """Search/metadata trimming: invisible and none hide a hit, while
    grants and no-rule keep it visible -- regardless of what native would
    have been, since the caller has no native permission to pass."""
    subjects = resolver.subject_set('u@e.com')

    def rules_for(permission, inherit=1):
        return [{'path': '/hr', 'subject_type': 'user',
                 'subject': 'u@e.com', 'permission': permission,
                 'inherit': inherit}]

    for permission in (resolver.PERMISSION_INVISIBLE, resolver.PERMISSION_NONE):
        assert resolver.denies(rules_for(permission), subjects, '/hr/a.txt')
        assert resolver.denies(rules_for(permission), subjects, '/hr')

    for permission in (resolver.PERMISSION_R, resolver.PERMISSION_RW):
        assert not resolver.denies(rules_for(permission), subjects, '/hr/a.txt')

    assert not resolver.denies([], subjects, '/hr/a.txt')


def test_denies_honours_non_inheriting_rule_and_deeper_override():
    """A non-inheriting invisible rule hides only its own path, and a deeper
    grant overrides an inherited deny -- both are cases a naive prefix set
    cannot express."""
    subjects = resolver.subject_set('u@e.com')

    non_inherit = [{'path': '/hr', 'subject_type': 'user',
                    'subject': 'u@e.com', 'permission': 'invisible',
                    'inherit': 0}]
    assert resolver.denies(non_inherit, subjects, '/hr')
    assert not resolver.denies(non_inherit, subjects, '/hr/a.txt')

    override = [
        {'path': '/hr', 'subject_type': 'user', 'subject': 'u@e.com',
         'permission': 'invisible', 'inherit': 1},
        {'path': '/hr/allowed', 'subject_type': 'user', 'subject': 'u@e.com',
         'permission': 'rw', 'inherit': 1},
    ]
    assert resolver.denies(override, subjects, '/hr/other.txt')
    assert not resolver.denies(override, subjects, '/hr/allowed/a.txt')


def test_never_widens():
    """The v3 eligibility invariant: a rule may set any value inside an
    existing grant (r -> rw promotion included), but a native of None stays
    None whatever the rules say -- a directory rule never manufactures
    access."""
    order = resolver.PERMISSION_ORDER
    subjects = resolver.subject_set('u@e.com')
    for decision in order:
        rules = [{'path': '/x', 'subject_type': 'user',
                  'subject': 'u@e.com', 'permission': decision,
                  'inherit': 1}]
        assert resolver.resolve(rules, subjects, '/x', None) is None
        # non-comparable natives are only ever vetoed, never reordered
        if decision not in (resolver.PERMISSION_INVISIBLE,
                            resolver.PERMISSION_NONE):
            got = resolver.resolve(rules, subjects, '/x', 'preview')
            assert got == 'preview', (decision, got)


def test_personal_track_beats_group_track_across_levels():
    """Direct unit form of the Pro cross-layer precedence: a personal rule
    inherited from the parent outranks a group rule on the deeper dir."""
    rules = [
        {'path': '/p', 'subject_type': 'user', 'subject': 'u@e.com',
         'permission': 'r', 'inherit': 1},
        {'path': '/p/sub', 'subject_type': 'group', 'subject': '1',
         'permission': 'rw', 'inherit': 1},
    ]
    subjects = resolver.subject_set('u@e.com', group_ids=['1'])
    assert resolver.resolve(rules, subjects, '/p/sub', 'rw') == 'r'
    assert resolver.resolve(rules, subjects, '/p/sub/x', 'rw') == 'r'


def test_personal_deny_beats_group_grant_but_group_track_alone_still_resolves():
    rules = [
        {'path': '/', 'subject_type': 'group', 'subject': '1',
         'permission': 'rw', 'inherit': 1},
        {'path': '/hr', 'subject_type': 'user', 'subject': 'u@e.com',
         'permission': 'none', 'inherit': 1},
    ]
    subjects = resolver.subject_set('u@e.com', group_ids=['1'])
    assert resolver.resolve(rules, subjects, '/hr/x', 'rw') is None
    assert resolver.resolve(rules, subjects, '/ok', 'rw') == 'rw'


def test_can_manage_grant_covers_descendants():
    subjects = resolver.subject_set('u@e.com')
    rules = [{'path': '/a', 'subject_type': 'user', 'subject': 'u@e.com',
              'inherit': 1}]
    assert resolver.can_manage(rules, subjects, '/a')
    assert resolver.can_manage(rules, subjects, '/a/b/c')
    assert not resolver.can_manage(rules, subjects, '/b')


def test_can_manage_non_inheriting_grant_covers_only_exact_path():
    subjects = resolver.subject_set('u@e.com')
    rules = [{'path': '/a', 'subject_type': 'user', 'subject': 'u@e.com',
              'inherit': 0}]
    assert resolver.can_manage(rules, subjects, '/a')
    assert not resolver.can_manage(rules, subjects, '/a/b')


def test_can_manage_root_grant_covers_everything():
    subjects = resolver.subject_set('u@e.com')
    rules = [{'path': '/', 'subject_type': 'user', 'subject': 'u@e.com',
              'inherit': 1}]
    assert resolver.can_manage(rules, subjects, '/deep/path/file.txt')


def test_can_manage_ignores_other_subjects_and_empty_rules():
    subjects = resolver.subject_set('u@e.com')
    other = [{'path': '/a', 'subject_type': 'user', 'subject': 'x@e.com',
              'inherit': 1}]
    assert not resolver.can_manage(other, subjects, '/a')
    assert not resolver.can_manage([], subjects, '/a')


def test_can_manage_group_grant():
    rules = [{'path': '/a', 'subject_type': 'group', 'subject': '1',
              'inherit': 1}]
    assert resolver.can_manage(rules, resolver.subject_set('u@e.com',
                                                           group_ids=['1']),
                               '/a/x')
    assert not resolver.can_manage(rules, resolver.subject_set('v@e.com',
                                                               group_ids=['2']),
                                   '/a/x')
