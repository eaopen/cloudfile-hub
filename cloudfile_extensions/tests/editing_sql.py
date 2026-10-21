"""Read production C SQL literals for shared database regression cases."""
import ast
from pathlib import Path
import re

WORKSPACE = Path(__file__).resolve().parents[3]

def checkout_queries(path, table="cf_edit_guard"):
    # Read adjacent C string literals without copying a second SQL definition.
    groups = re.findall(r'(?:"(?:[^"\\]|\\.)*"\s*)+', path.read_text())
    result = []
    for group in groups:
        literals = re.findall(r'"(?:[^"\\]|\\.)*"', group)
        query = ''.join(ast.literal_eval(literal) for literal in literals)
        if query.startswith('SELECT r.uid') and ('JOIN ' + table) in query:
            result.append(query)
    return result


def native_intent_query(path):
    groups = re.findall(r'(?:"(?:[^"\\]|\\.)*"\s*)+', path.read_text())
    matches = []
    for group in groups:
        query = ''.join(ast.literal_eval(literal) for literal in
            re.findall(r'"(?:[^"\\]|\\.)*"', group))
        if query.startswith('SELECT i.action FROM cf_resource r JOIN cf_edit_guard g'):
            matches.append(query)
    if len(matches) != 1:
        raise ValueError('one native publication predicate required')
    return matches[0]


def native_publication_updates(path):
    groups = re.findall(r'(?:"(?:[^"\\]|\\.)*"\s*)+', path.read_text())
    queries = []
    for group in groups:
        query = ''.join(ast.literal_eval(literal) for literal in
            re.findall(r'"(?:[^"\\]|\\.)*"', group))
        if (query.startswith("UPDATE cf_commit_intent SET state='published'") or
                query.startswith('UPDATE cf_edit_guard SET guard_id=NULL,') or
                query.startswith('UPDATE cf_edit_guard SET base_file_id=?,pending_intent=NULL')):
            queries.append(query)
    if len(queries) != 3:
        raise ValueError('three native publication mutations required')
    return queries
