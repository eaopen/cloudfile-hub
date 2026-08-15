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
    """The security invariant, checked exhaustively over the lattice."""
    order = resolver.PERMISSION_ORDER
    for native in ('r', 'rw'):
        for decision in order:
            rules = [{'path': '/x', 'subject_type': 'user',
                      'subject': 'u@e.com', 'permission': decision,
                      'inherit': 1}]
            subjects = resolver.subject_set('u@e.com')
            got = resolver.resolve(rules, subjects, '/x', native)
            if got is None:
                continue
            assert order[got] <= order[native], (native, decision, got)
