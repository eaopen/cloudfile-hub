# -*- coding: utf-8 -*-
"""The authorisation rule: access comes from a grant, never from its absence.

Every test here is one way the rule could fail *open*. That bias is deliberate:
a rule that wrongly denies produces a support ticket, and a rule that wrongly
grants produces a breach nobody reports.

Django-free -- authz.py exists precisely so this file needs no stack.
"""

import pytest

from cloudfile_ext.external_sources import authz
from cloudfile_ext.external_sources.authz import (
    PERMISSION_R, SUBJECT_GROUP, SUBJECT_USER, decide,
)


def test_no_grants_is_no_access():
    assert decide([]) is None


def test_user_grant_grants():
    # Rows reaching decide() are already narrowed to this user, so a user row
    # being present *is* the match -- see the docstring on decide().
    assert decide([(SUBJECT_USER, 'u@auth.local', PERMISSION_R)]) == PERMISSION_R


def test_group_grant_requires_membership():
    grants = [(SUBJECT_GROUP, '7', PERMISSION_R)]
    assert decide(grants, group_ids=[7]) == PERMISSION_R
    assert decide(grants, group_ids=[8]) is None
    assert decide(grants, group_ids=[]) is None


def test_group_ids_compare_as_strings():
    """A group subject is stored as text; ints must still match.

    The column holds subjects of both kinds, so the id arrives as '7' from the
    database and as 7 from ccnet. A rule that compared them directly would deny
    every group grant, and it would do so silently.
    """
    assert decide([(SUBJECT_GROUP, '7', PERMISSION_R)], group_ids=[7]) \
        == PERMISSION_R
    assert decide([(SUBJECT_GROUP, 7, PERMISSION_R)], group_ids=['7']) \
        == PERMISSION_R


def test_disabled_source_denies_everyone_including_staff():
    """Disabling is not cosmetic, and staff are not an exception to it.

    An administrator disables a source when the mount is wrong or the share
    must be pulled; the one thing that must not happen is it staying readable
    for the people who can also see everything else.
    """
    grants = [(SUBJECT_USER, 'u@auth.local', PERMISSION_R)]
    assert decide(grants, enabled=False) is None
    assert decide(grants, is_staff=True, enabled=False) is None
    assert decide([], is_staff=True, enabled=False) is None


def test_staff_read_without_a_grant():
    assert decide([], is_staff=True) == PERMISSION_R


def test_unknown_permission_is_ignored_not_honoured():
    """A value outside the domain must not grant anything.

    'rw' is the value somebody will write when read-write support arrives, and
    a rule that passes it through would silently start granting writes on a
    release that cannot enforce them.
    """
    assert decide([(SUBJECT_USER, 'u@auth.local', 'rw')]) is None
    assert decide([(SUBJECT_USER, 'u@auth.local', '')]) is None
    assert decide([(SUBJECT_GROUP, '7', 'admin')], group_ids=[7]) is None


def test_unknown_subject_type_is_ignored():
    assert decide([('department', '3', PERMISSION_R)], group_ids=[3]) is None
    assert decide([('', '', PERMISSION_R)]) is None


def test_a_bad_row_does_not_shadow_a_good_one():
    """Ignoring an unusable row must not abort the scan.

    A `break` or an early return where the code has `continue` would let one
    malformed grant revoke a legitimate one -- a failure that only shows up
    once some deployment has a stale row.
    """
    grants = [
        ('department', '3', PERMISSION_R),
        (SUBJECT_USER, 'u@auth.local', 'rw'),
        (SUBJECT_GROUP, '7', PERMISSION_R),
    ]
    assert decide(grants, group_ids=[7]) == PERMISSION_R


def test_read_only_is_the_entire_domain():
    """Guards the release boundary rather than the code shape.

    If read-write is ever added, this fails and forces the spec, the API
    validation and docs/external-sources.md to be revisited together instead of
    a second value appearing because one call site allowed it.
    """
    assert authz.VALID_PERMISSIONS == (PERMISSION_R,)
    assert set(authz.VALID_SUBJECT_TYPES) == {SUBJECT_USER, SUBJECT_GROUP}


@pytest.mark.parametrize('is_staff,group_ids,grants,expected', [
    (False, [], [], None),
    (False, [1, 2], [(SUBJECT_GROUP, '2', PERMISSION_R)], PERMISSION_R),
    (True, [], [], PERMISSION_R),
])
def test_decision_table(is_staff, group_ids, grants, expected):
    assert decide(grants, is_staff=is_staff, group_ids=group_ids) == expected
