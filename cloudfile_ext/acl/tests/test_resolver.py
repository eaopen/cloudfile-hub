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
