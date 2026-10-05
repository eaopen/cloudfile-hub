"""Bounded directory/file repair for the legacy Meili name/tag index.

Repair runs outside user queries. Each page is pinned to one native commit,
includes empty directories and advances only after the index write succeeds.
Files are leaves: their document is built from the native entry alone, and they
are never queued for descent.

`build_document(path, mtime, object_type, entry)` is the callback contract. The
validated native listing `entry` is handed to it alongside the path/kind so the
callback can build the document from values the listing already returned
(`obj_id`, `obj_name`, `mode`, `mtime`, `size`) instead of paying a native RPC
per file. `mtime` is still passed for callers that only need the timestamp, and
entries that lack what such a fast path reads simply make the caller fall back
to its RPC-based builder.
"""
import stat

PAGE_SIZE = 100

#: Object kinds the legacy index can hold. `dir` writes a document per directory,
#: `file` writes metadata-only documents per regular file. Both walk the tree:
#: directories are always descended, because that is the only way to reach files
#: nested inside them.
KINDS = ('dir', 'file')


def advance_page(state, *, read_page, build_document, write_documents, assert_current,
                 kinds=('dir',)):
    if any(kind not in KINDS for kind in kinds):
        raise ValueError('invalid backfill kinds')
    pending = [dict(position) for position in state['pending']]
    if not pending:
        return state
    assert_current()
    position = pending.pop()
    entries = read_page(position['path'], position['offset'], PAGE_SIZE + 1)
    if not isinstance(entries, (list, tuple)) or len(entries) > PAGE_SIZE + 1:
        raise ValueError('invalid native directory page')
    documents, children, names = [], [], set()
    files = 0
    for entry in entries[:PAGE_SIZE]:
        name = getattr(entry, 'obj_name', None)
        mode = getattr(entry, 'mode', None)
        if (not isinstance(name, str) or name in ('', '.', '..') or '/' in name or '\0' in name
                or name in names or type(mode) is not int or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode))):
            raise ValueError('invalid native directory entry')
        names.add(name)
        path = ('' if position['path'] == '/' else position['path']) + '/' + name
        if stat.S_ISDIR(mode):
            if len(path.encode('utf-8')) > 4096:
                raise ValueError('directory path exceeds budget')
            # Directories always drive descent: a file-only run still has to
            # walk through them to reach files, it just builds no dir document.
            children.append(dict(path=path, offset=0))
            if 'dir' not in kinds:
                continue
            document = build_document(path, getattr(entry, 'mtime', 0), 'dir', entry)
            if document is None:
                raise ValueError('directory changed during backfill')
            documents.append(document)
        else:
            if 'file' not in kinds:
                continue
            document = build_document(path, getattr(entry, 'mtime', 0), 'file', entry)
            if document is None:
                raise ValueError('file changed during backfill')
            documents.append(document)
            files += 1
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
                directories=state.get('directories', 0) + len(documents) - files,
                files=state.get('files', 0) + files)
