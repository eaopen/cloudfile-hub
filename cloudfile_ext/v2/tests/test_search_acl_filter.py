"""The search pre-filter against the real V2 Authority on randomized rule trees.

The generated Meilisearch string is parsed and evaluated here on the same
`path`/`dirs` document fields the worker indexes. Invariants:
- never exclude a readable object (Authority stays the access decision);
- equal Authority wherever the region is unambiguous.
"""
import json
import posixpath
import random
import re
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from cloudfile_ext.v2.acl_policy import Principal, Rule, within
from cloudfile_ext.v2.acl_runtime import Authority
from cloudfile_ext.v2.search import acl_filter
from cloudfile_ext.v2.search.documents import ancestor_paths

RID = '00000000-0000-4000-8000-000000000001'
P = Principal('external', 'uid', frozenset({('org', 'directory', 'o1'), ('role', 'role', 'r1')}))
SUBJECTS = (('user', 'user', 'uid'), ('user', 'user', 'other'), ('org', 'directory', 'o1'),
            ('org', 'directory', 'o2'), ('role', 'role', 'r1'))
TOKEN = re.compile(r'\s*(\(|\)|\[|\]|,|=|"(?:[^"\\]|\\.)*"|[A-Za-z_]+)')


def evaluate(expression, doc):
    """Meilisearch filter subset used by search: NOT > AND > OR, = and IN."""
    tokens, position = [], 0
    while position < len(expression):
        match = TOKEN.match(expression, position)
        if not match:
            raise AssertionError('unparsable filter at %d: %r' % (position, expression[position:]))
        tokens.append(match.group(1))
        position = match.end()
    tokens.append(None)
    index = 0

    def peek():
        return tokens[index]

    def take(expected=None):
        nonlocal index
        token = tokens[index]
        if expected is not None and token != expected:
            raise AssertionError('expected %r got %r' % (expected, token))
        index += 1
        return token

    def string():
        token = take()
        assert token.startswith('"'), token
        return json.loads(token)

    def atom():
        if peek() == '(':
            take('(')
            value = disjunction()
            take(')')
            return value
        field = take()
        assert field in ('path', 'dirs'), field
        values = doc[field] if field == 'dirs' else [doc[field]]
        if peek() == '=':
            take('=')
            return string() in values
        take('IN')
        take('[')
        listed = [string()]
        while peek() == ',':
            take(',')
            listed.append(string())
        take(']')
        return any(value in listed for value in values)

    def negation():
        if peek() == 'NOT':
            take('NOT')
            return not negation()
        return atom()

    def conjunction():
        value = negation()
        while peek() == 'AND':
            take('AND')
            value = negation() and value
        return value

    def disjunction():
        value = conjunction()
        while peek() == 'OR':
            take('OR')
            value = conjunction() or value
        return value

    result = disjunction()
    assert peek() is None, tokens[index:]
    return result


def authority(rules, base):
    store = Mock()
    store.library.return_value = tuple(rules)
    api = Mock()
    api.get_repo.return_value = SimpleNamespace(is_virtual=False, version=1)
    api.get_repo_status.return_value = 0
    api.check_permission.return_value = base
    return Authority('native@auth.local', principal=P, rules=store, api=api)


def probe(anchor, paths):
    """A directory below anchor that is not a rule path: decides anchor's region."""
    taken = {p[len(anchor):].strip('/').split('/')[0] for p in paths if p != anchor and within(p, anchor)}
    name = 'cf-search-probe'
    while name in taken:
        name += '_'
    return posixpath.join(anchor, name)


def tree(segments, depth):
    paths, level = [], ['/']
    for _ in range(depth):
        level = [posixpath.join(parent, name) for parent in level for name in segments]
        paths.extend(level)
    return paths


class FilterConsistencyTests(TestCase):
    def setUp(self):
        ttl = patch('cloudfile_ext.v2.acl_runtime.cache_ttl', return_value=0)
        ttl.start()
        self.addCleanup(ttl.stop)

    def check(self, rules, base, directories):
        auth = authority(rules, base)
        view = auth.library_view(RID)
        paths = {rule.path for rule in view['rules']}
        readable = lambda path: auth.effective(RID, path).can_read
        expression = acl_filter.build(paths, readable)
        docs = [(path, 'dir') for path in directories] + [(posixpath.join(d, 'f.txt'), 'file') for d in ['/'] + directories]
        for path, kind in docs:
            truth = auth.effective(RID, path, kind).can_read
            doc = dict(path=path, dirs=ancestor_paths(path))
            if expression is None:
                matched = True
            elif expression is acl_filter.NOTHING:
                matched = False
            else:
                matched = evaluate(expression, doc)
            context = dict(rules=rules, base=base, path=path, kind=kind, filter=expression)
            if truth:
                self.assertTrue(matched, context)
            region = max([p for p in paths if p in doc['dirs']] or ['/'], key=len)
            inside = readable(probe(region, paths))
            # Anything readable inside a region requires the region root readable.
            self.assertTrue(readable(region) or not inside, context)
            unambiguous = readable(region) == inside
            if unambiguous and not (kind == 'dir' and path in paths):
                self.assertEqual(matched, truth, context)
        return expression

    def test_randomized_rule_trees_agree_with_authority(self):
        rng = random.Random(20261018)
        directories = tree(['a', 'b', 'cf-search-probe'], 3)
        for _ in range(1500):
            rules, keys = [], set()
            for _ in range(rng.randint(0, 6)):
                path = rng.choice(['/'] + directories)
                subject = rng.choice(SUBJECTS)
                if (path,) + subject in keys:
                    continue
                keys.add((path,) + subject)
                permission = rng.choice(('r', 'rw', 'invisible'))
                share = permission != 'invisible' and path != '/' and rng.random() < 0.4
                rules.append(Rule(RID, path, 'external', *subject, permission, rng.random() < 0.7, share))
            self.check(rules, rng.choice((None, 'r', 'rw')), directories)

    def test_rule_at_library_root_no_longer_disables_search(self):
        rules = [Rule(RID, '/', 'external', 'org', 'directory', 'o1', 'r'),
                 Rule(RID, '/a', 'external', 'user', 'user', 'uid', 'invisible')]
        expression = self.check(rules, 'rw', tree(['a', 'b'], 3))
        self.assertEqual(expression, '(NOT dirs IN ["/a"])')

    def test_directory_only_share_is_confined_to_its_root(self):
        rules = [Rule(RID, '/a/b', 'external', 'user', 'user', 'uid', 'r', True, True)]
        expression = self.check(rules, None, tree(['a', 'b'], 3))
        self.assertEqual(expression, '(dirs IN ["/a/b"] OR path IN ["/a/b"])')

    def test_no_rules_or_no_access(self):
        self.assertIsNone(self.check([], 'r', tree(['a'], 2)))
        rules = [Rule(RID, '/', 'external', 'user', 'user', 'uid', 'invisible')]
        self.assertIs(self.check(rules, 'rw', tree(['a'], 2)), acl_filter.NOTHING)

    def test_values_are_quoted_and_budgeted(self):
        name = '/设计 "x"'
        expression = acl_filter.build({name}, lambda path: not within(path, name))
        self.assertEqual(expression, '(NOT dirs IN ["/设计 \\"x\\""])')
        self.assertFalse(evaluate(expression, dict(path=name + '/f', dirs=[name])))
        with self.assertRaises(acl_filter.FilterUnavailable):
            acl_filter.build({'/p%d' % i for i in range(acl_filter.MAX_RULE_PATHS + 1)}, lambda path: True)
        with patch.object(acl_filter, 'MAX_FILTER_BYTES', 10), self.assertRaises(acl_filter.FilterUnavailable):
            acl_filter.build({'/a'}, lambda path: path == '/')
