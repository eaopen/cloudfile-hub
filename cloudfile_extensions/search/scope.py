"""Directory boundaries shared by projection and candidate filtering."""
from ..resources.paths import normalize_path


def ancestor_dirs(path, kind):
    # Exact ancestor tokens implement a subtree filter without a tree walk or
    # a lexical prefix accidentally including a sibling such as /ab under /a.
    path = normalize_path(path, kind)
    if path == '/':
        return []
    segments = path.split('/')[1:-1]
    return ['/'] + ['/' + '/'.join(segments[:i]) for i in range(1, len(segments) + 1)]
