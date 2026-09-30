"""Pure index projection from trusted native enumeration and sparse metadata.

No database allocation, user snapshot, native content hash identity or project
UG mapping. Consumers must still enforce source ordering and lifecycle fences.
"""
import hashlib
import json

from ..common.errors import invalid
from ..common.validation import identifier, sequence
from ..resources.paths import resource_ref
from ..tags.definitions import label_value, uuid_value
from .scope import ancestor_dirs


INDEX_SETTINGS = {
    "searchableAttributes": ["name", "path", "description", "tag_labels", "tag_codes"],
    "filterableAttributes": ["repo_id", "kind", "tag_ids", "dirs"],
    "displayedAttributes": ["repo_id", "path", "kind"],
}


def document_key(reference):
    ref = resource_ref(reference)
    try:
        raw = json.dumps([ref["repo_id"], ref["path"], ref["kind"]], ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(ref["path"].encode("utf-8")) > 4096:
            raise ValueError()
    except (UnicodeError, ValueError):
        raise invalid("Invalid indexed resource path") from None
    return hashlib.sha256(b"cf.search.resource.v1\n" + raw).hexdigest()


def resource_document(reference, *, source_sequence, annotation=None):
    ref = resource_ref(reference)
    key = document_key(ref)
    sequence(source_sequence)
    description, tag_ids, labels, codes, uid = "", [], [], [], None
    if annotation is not None:
        if not isinstance(annotation, dict) or annotation.get("resource") != ref:
            raise invalid("Indexed annotation target mismatch")
        description = annotation.get("description")
        if not isinstance(description, str) or len(description) > 4096:
            raise invalid("Invalid indexed description")
        try:
            description.encode("utf-8")
        except UnicodeError:
            raise invalid("Invalid indexed description") from None
        uid = annotation.get("uid")
        if uid is not None:
            uuid_value(uid)
        tags = annotation.get("tags")
        if not isinstance(tags, list) or len(tags) > 128:
            raise invalid("Invalid indexed tags")
        seen = set()
        for tag in tags:
            if not isinstance(tag, dict):
                raise invalid("Invalid indexed tag")
            tag_id = uuid_value(tag.get("tag_id"))
            if tag_id in seen or tag.get("kind") not in ("system", "user") or type(tag.get("enabled")) is not bool:
                raise invalid("Invalid indexed tag")
            seen.add(tag_id)
            label = label_value(tag.get("label"))
            code = identifier(tag.get("code"), maximum=128)
            if tag.get("scope_repo_id") not in (None, ref["repo_id"]):
                raise invalid("Indexed tag repository mismatch")
            if tag["enabled"]:
                tag_ids.append(tag_id)
                labels.append(label)
                codes.append(code)
    return dict(id=key, **ref, dirs=ancestor_dirs(ref["path"], ref["kind"]),
        name=ref["path"].rsplit("/", 1)[-1], description=description,
        tag_ids=tag_ids, tag_labels=labels, tag_codes=codes, resource_uid=uid, source_sequence=source_sequence)
