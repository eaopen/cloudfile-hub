"""Batch legacy tags using the existing native consistency checks, not 4A."""
from copy import deepcopy
import posixpath
import stat

from .contract import MODEL, VERSION


def resolve(repo_id, items, access, lookup, load_tags):
    # Hub preserves duplicate slots; EAP's existing public DTO independently
    # keeps first occurrences only. Neither layer repeats loads for duplicates.
    unique = list(dict.fromkeys(items))
    access.prepare_many([target for path, _ in unique
                         for target in (posixpath.dirname(path) or '/', path)])
    results, allowed = {}, []
    for path, is_dir in unique:
        item = dict(path=path, is_dir=is_dir, status='DENIED', tags=None)
        if access(posixpath.dirname(path) or '/') and access(path):
            try:
                entry = lookup(path, is_dir)
                exists = entry is not None and (stat.S_ISDIR(entry.mode) if is_dir else stat.S_ISREG(entry.mode))
                if exists:
                    allowed.append((path, is_dir))
                    item['status'] = 'OK'
                else:
                    item['status'] = 'NOT_FOUND'
            except Exception:
                # Preserve per-object failure semantics without treating a
                # provider error as a missing object or an empty tag list.
                item['status'] = 'FAILED'
        results[(path, is_dir)] = item
    loaded = load_tags(allowed)
    if set(loaded) != set(allowed):
        raise ValueError('Incomplete legacy tag collection')
    for key in allowed:
        results[key]['tags'] = loaded[key]
    return dict(version=VERSION, model=MODEL, repo_id=repo_id,
                items=[deepcopy(results[key]) for key in items])
