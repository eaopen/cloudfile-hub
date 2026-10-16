"""Pure Meilisearch document projection from authenticated CE file facts.

This module does not read the database, parse file bytes or grant access.
Callers must provide facts from the current native file/tree and Tag models.
"""

import hashlib
import json
from uuid import UUID


INDEX_SETTINGS = {
    "searchableAttributes": ["name", "tag_labels", "description", "path", "content"],
    "filterableAttributes": ["repo_id", "path", "kind", "extension", "ancestor_paths", "tag_keys"],
    "sortableAttributes": ["mtime", "size", "name"],
}


class InvalidIndexDocument(ValueError):
    pass


def _repo(value):
    try:
        return str(UUID(value))
    except (ValueError, AttributeError, TypeError):
        raise InvalidIndexDocument("invalid repository identifier") from None


def _path(value):
    try:
        if (not isinstance(value, str) or not value.startswith("/") or
                value == "/" or value.endswith("/") or "//" in value or
                any(part in (".", "..") for part in value.split("/")) or
                chr(0) in value or len(value.encode("utf-8")) > 4096):
            raise ValueError()
    except (ValueError, UnicodeError):
        raise InvalidIndexDocument("path must be normalized and non-root") from None
    return value


def ancestor_paths(path):
    """Exact path-segment parents: /A/B/file -> ['/A', '/A/B']."""
    parts = path.strip("/").split("/")[:-1]
    return ["/" + "/".join(parts[:i]) for i in range(1, len(parts) + 1)]


def document_id(*, repo_id, path, kind):
    reference = json.dumps([_repo(repo_id), _path(path), kind], ensure_ascii=False,
                           separators=(",", ":")).encode("utf-8")
    if kind not in ("file", "dir"):
        raise InvalidIndexDocument("invalid object kind")
    return hashlib.sha256(b"cloudfile.v2.search\\n" + reference).hexdigest()


def index_document(*, repo_id, path, kind, size=0, mtime=0,
                   tags=(), description="", content=""):
    """Build one disposable index document; content is supplied, never extracted.

    tags: iterable of {'key': stable CE RepoTag key, 'label': display name}.
    Missing tags and unavailable description/parsed content are empty values.
    Tag read failures belong to the caller and must not masquerade as no tags.
    """
    rid, filename, target = _repo(repo_id), None, _path(path)
    if kind not in ("file", "dir"):
        raise InvalidIndexDocument("invalid object kind")
    if any(type(value) is not int or value < 0 for value in (size, mtime)):
        raise InvalidIndexDocument("invalid size or mtime")
    if (not isinstance(tags, (list, tuple)) or len(tags) > 128 or
            not isinstance(description, str) or len(description) > 4096 or
            not isinstance(content, str) or len(content) > 32768):
        raise InvalidIndexDocument("invalid indexed attributes")
    try:
        description.encode("utf-8")
        content.encode("utf-8")
        keys, labels, seen = [], [], set()
        for item in tags:
            if not isinstance(item, dict) or set(item) != {"key", "label"}:
                raise ValueError()
            key, label = item["key"], item["label"]
            if (not isinstance(key, str) or not key or len(key) > 255 or
                    not isinstance(label, str) or not label or len(label) > 255):
                raise ValueError()
            key.encode("utf-8")
            label.encode("utf-8")
            if key not in seen:
                keys.append(key)
                labels.append(label)
                seen.add(key)
    except (ValueError, UnicodeError):
        raise InvalidIndexDocument("invalid CE Tag or text") from None
    filename = target.rsplit("/", 1)[-1]
    extension = ""
    if kind == "file" and not filename.startswith(".") and "." in filename:
        extension = filename.rsplit(".", 1)[-1].lower()
    return dict(id=document_id(repo_id=rid, path=target, kind=kind), repo_id=rid,
                path=target, name=filename, kind=kind, extension=extension,
                ancestor_paths=ancestor_paths(target), tag_keys=keys, tag_labels=labels,
                description=description, content=content, mtime=mtime, size=size)
