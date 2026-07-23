# -*- coding: utf-8 -*-
"""Structured filters for search providers.

This module exists to keep two capabilities on two branches.

Combined retrieval -- "files tagged 合同, whose 部门 is 法务, containing 违约金"
-- needs both the metadata capability (which owns the fields) and the search
capability (which owns the index). Without a shared vocabulary, that feature
has to live on one of them, and that branch then cannot be developed or
verified without the other: the two capabilities collapse into one large
branch with one long acceptance cycle.

With this vocabulary, they stay apart:

    metadata  declares fields and feeds them to whatever indexer is registered,
              and issues queries in these terms
    search    translates these terms into its backend's own filter syntax
              (meilisearch filter expressions, seasearch DSL, SQL, ...)

Each verifies alone -- metadata against a fake provider that records what it
was asked, search against synthetic documents. Only the end-to-end combination
needs both, and that belongs to the integration gate on dev, not to either
branch.

Note this is deliberately *not* the same thing as upstream's ``obj_desc``,
which carries file-intrinsic properties (type, suffix, mtime, size). These are
user-defined attributes and tags. The two are orthogonal and both are passed.
"""

#: Comparison operators. Kept small on purpose -- every operator here has to be
#: implementable by every backend we might plug in, and a vocabulary that
#: outgrows its weakest backend just moves the incompatibility to runtime.
EQ = 'eq'
NE = 'ne'
IN = 'in'
CONTAINS = 'contains'
GT = 'gt'
GTE = 'gte'
LT = 'lt'
LTE = 'lte'
EXISTS = 'exists'

OPS = frozenset({EQ, NE, IN, CONTAINS, GT, GTE, LT, LTE, EXISTS})

#: Operators whose value must be a sequence.
_SEQUENCE_OPS = frozenset({IN})
#: Operators that take no value.
_NULLARY_OPS = frozenset({EXISTS})


class InvalidFilter(Exception):
    """The filter itself is malformed."""


class UnsupportedFilter(Exception):
    """The selected provider cannot honour this filter.

    Raised rather than dropping the filter. A silently ignored predicate
    returns *more* rows than were asked for, and the caller cannot tell the
    difference between "nothing matched that tag" and "the tag was ignored" --
    the result set looks perfectly plausible either way. Refusing is the only
    honest answer a backend can give here.
    """


class FieldFilter(object):
    """One predicate over a user-defined attribute or tag."""

    __slots__ = ('field', 'op', 'value')

    def __init__(self, field, op, value=None):
        if not field or not isinstance(field, str):
            raise InvalidFilter('field must be a non-empty string: %r' % (field,))
        if op not in OPS:
            raise InvalidFilter('unknown operator %r; known: %s'
                                % (op, sorted(OPS)))
        if op in _NULLARY_OPS:
            value = None
        elif op in _SEQUENCE_OPS:
            if not isinstance(value, (list, tuple, set, frozenset)):
                raise InvalidFilter('%r needs a sequence value, got %r'
                                    % (op, type(value).__name__))
            value = list(value)
            if not value:
                # An empty IN matches nothing. Almost always a caller bug --
                # and one that presents as "the index is broken".
                raise InvalidFilter('%r with an empty sequence matches nothing'
                                    % (op,))
        elif value is None:
            raise InvalidFilter('%r needs a value' % (op,))

        self.field = field
        self.op = op
        self.value = value

    def as_dict(self):
        return {'field': self.field, 'op': self.op, 'value': self.value}

    def __eq__(self, other):
        return (isinstance(other, FieldFilter)
                and self.as_dict() == other.as_dict())

    def __hash__(self):
        value = tuple(self.value) if isinstance(self.value, list) else self.value
        return hash((self.field, self.op, value))

    def __repr__(self):
        return 'FieldFilter(%r, %r, %r)' % (self.field, self.op, self.value)


def parse(raw):
    """Build FieldFilters from a list of dicts (e.g. decoded from a request)."""
    if not raw:
        return []
    if isinstance(raw, dict):
        raise InvalidFilter('filters must be a list of predicates, not a dict')
    out = []
    for item in raw:
        if isinstance(item, FieldFilter):
            out.append(item)
            continue
        if not isinstance(item, dict):
            raise InvalidFilter('each filter must be a dict: %r' % (item,))
        unknown = set(item) - {'field', 'op', 'value'}
        if unknown:
            # A typo'd key would otherwise be dropped, which silently widens
            # the query -- the same failure UnsupportedFilter exists to avoid.
            raise InvalidFilter('unknown filter keys: %s' % sorted(unknown))
        out.append(FieldFilter(item.get('field'), item.get('op'),
                               item.get('value')))
    return out


def supported_ops(provider):
    """Operators `provider` declares it can honour.

    Absent declaration means none: a backend written before this vocabulary
    existed must not be assumed to implement it. Defaulting the other way
    would make every old provider silently ignore every filter.
    """
    return frozenset(getattr(provider, 'supported_filter_ops', ()) or ())


def check_supported(provider, filters):
    """Raise UnsupportedFilter unless `provider` can honour every filter."""
    if not filters:
        return
    declared = supported_ops(provider)
    missing = sorted({f.op for f in filters} - declared)
    if missing:
        raise UnsupportedFilter(
            'the selected search provider does not support %s '
            '(it declares %s). Refusing rather than returning results that '
            'ignore the filter.' % (missing, sorted(declared) or 'nothing'))
