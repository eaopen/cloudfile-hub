# -*- coding: utf-8 -*-
"""Structured search filters.

The property worth protecting here is not "filters work" -- it is that a
filter is never silently dropped. Every way of losing a predicate (an
undeclared operator, a typo'd key, no provider at all) has to raise, because a
dropped predicate returns a larger result set that looks entirely plausible.

Pure logic, no Django needed; see test_providers for why that matters.
"""

import pytest

from cloudfile_ext import search_query as sq


# -- construction ---------------------------------------------------------

def test_rejects_unknown_operator():
    with pytest.raises(sq.InvalidFilter):
        sq.FieldFilter('部门', 'approximately', '法务')


def test_rejects_empty_field():
    with pytest.raises(sq.InvalidFilter):
        sq.FieldFilter('', sq.EQ, 'x')


def test_in_requires_a_sequence():
    with pytest.raises(sq.InvalidFilter):
        sq.FieldFilter('tag', sq.IN, '合同')


def test_empty_in_is_rejected():
    """An empty IN matches nothing and presents as 'the index is broken'."""
    with pytest.raises(sq.InvalidFilter):
        sq.FieldFilter('tag', sq.IN, [])


def test_exists_takes_no_value():
    f = sq.FieldFilter('部门', sq.EXISTS, 'ignored')
    assert f.value is None


def test_binary_operator_needs_a_value():
    with pytest.raises(sq.InvalidFilter):
        sq.FieldFilter('部门', sq.EQ, None)


# -- parsing ---------------------------------------------------------------

def test_parse_builds_filters():
    got = sq.parse([{'field': '部门', 'op': sq.EQ, 'value': '法务'}])
    assert got == [sq.FieldFilter('部门', sq.EQ, '法务')]


def test_parse_passes_through_existing_filters():
    f = sq.FieldFilter('部门', sq.EQ, '法务')
    assert sq.parse([f]) == [f]


def test_parse_rejects_unknown_keys():
    """An unrecognised key would be dropped, silently widening the query.

    The predicate here is otherwise *valid* on purpose. An earlier version of
    this test used {'field', 'operator', 'value'} -- a misspelt 'op' -- which
    still raised once the unknown-key check was removed, because 'op' was then
    missing. It passed for the wrong reason and a mutation caught it.
    """
    with pytest.raises(sq.InvalidFilter):
        sq.parse([{'field': '部门', 'op': sq.EQ, 'value': '法务', 'boost': 2}])


def test_parse_of_nothing_is_empty():
    assert sq.parse(None) == []
    assert sq.parse([]) == []


# -- provider capability negotiation --------------------------------------

class Declaring(object):
    supported_filter_ops = frozenset({sq.EQ, sq.IN})


class Silent(object):
    """A backend written before this vocabulary existed."""


def test_undeclared_provider_supports_nothing():
    # Defaulting the other way would make every pre-existing provider
    # silently ignore every filter -- the exact failure this module prevents.
    assert sq.supported_ops(Silent()) == frozenset()


def test_declared_operators_pass():
    sq.check_supported(Declaring(),
                       [sq.FieldFilter('部门', sq.EQ, '法务')])


def test_undeclared_operator_is_refused():
    with pytest.raises(sq.UnsupportedFilter) as exc:
        sq.check_supported(Declaring(),
                           [sq.FieldFilter('大小', sq.GT, 100)])
    # The message must name what is missing and what is available, or the
    # operator cannot tell a backend limitation from a typo.
    assert sq.GT in str(exc.value)


def test_silent_provider_is_refused_any_filter():
    with pytest.raises(sq.UnsupportedFilter):
        sq.check_supported(Silent(), [sq.FieldFilter('部门', sq.EQ, '法务')])


def test_no_filters_never_raises():
    """Providers that predate filters must keep working untouched."""
    sq.check_supported(Silent(), [])
    sq.check_supported(Silent(), None)
