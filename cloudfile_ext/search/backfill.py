"""Bounded directory-only repair for the legacy Meili name/tag index.

Repair runs outside user queries. Each page is pinned to one native commit,
includes empty directories and advances only after the index write succeeds.
"""
import stat

PAGE_SIZE = 100


def advance_page(state, *, read_page, build_document, write_documents, assert_current):
    pending = [dict(position) for position in state['pending']]
    if not pending:
        return state
    assert_current()
    position = pending.pop()
    entries = read_page(position['path'], position['offset'], PAGE_SIZE + 1)
    if not isinstance(entries, (list, tuple)) or len(entries) > PAGE_SIZE + 1:
        raise ValueError('invalid native directory page')
    documents, children, names = [], [], set()
    for entry in entries[:PAGE_SIZE]:
        name = getattr(entry, 'obj_name', None)
        mode = getattr(entry, 'mode', None)
        if (not isinstance(name, str) or name in ('', '.', '..') or '/' in name or '\0' in name
                or name in names or type(mode) is not int or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode))):
            raise ValueError('invalid native directory entry')
        names.add(name)
        if not stat.S_ISDIR(mode):
            continue
        path = ('' if position['path'] == '/' else position['path']) + '/' + name
        if len(path.encode('utf-8')) > 4096:
            raise ValueError('directory path exceeds budget')
        document = build_document(path, getattr(entry, 'mtime', 0))
        if document is None:
            raise ValueError('directory changed during backfill')
        documents.append(document)
        children.append(dict(path=path, offset=0))
    # Keep a depth-first continuation rather than a whole-library in-memory tree.
    if len(entries) > PAGE_SIZE:
        pending.append(dict(path=position['path'], offset=position['offset'] + PAGE_SIZE))
    pending.extend(reversed(children))
    if len(pending) > 10000:
        raise ValueError('directory continuation exceeds budget')
    assert_current()
    if documents:
        write_documents(documents)
    assert_current()
    return dict(state, pending=pending, pages=state.get('pages', 0) + 1,
                directories=state.get('directories', 0) + len(documents))
