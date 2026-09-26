"""Build one complete bounded tag page from coherent native/SQL snapshots.

Trusted caller owns the cursor transaction and native lifecycle scope. This
helper never commits, allocates resources or writes to Meilisearch itself.
"""
import json
import time

from ..common.errors import ContractError
from ..common.validation import sequence
from ..resources.paths import resource_ref
from .documents import resource_document
from .tag_fanout import binding_page


def project_binding_page(cursor, *, repo_id, tag_id, revision, upper_uid, after,
                         source_sequence, snapshot_reader, clock=time.monotonic):
    if not callable(snapshot_reader):
        raise ValueError("trusted same-scope native snapshot reader required")
    sequence(source_sequence)
    deadline = clock() + 20
    page = binding_page(cursor, repo_id=repo_id, tag_id=tag_id, revision=revision,
        upper_uid=upper_uid, after=after, limit=100)
    documents = []
    for item in page["items"]:
        if clock() >= deadline:
            raise ContractError("SEARCH_PROJECTION_PENDING", "Tag projection deadline exceeded", 503)
        snapshot = snapshot_reader(cursor, item["reference"])
        if (not isinstance(snapshot, dict) or not isinstance(snapshot.get("resource"), dict) or
                resource_ref(snapshot["resource"]) != item["reference"] or snapshot.get("uid") != item["resource_uid"]):
            raise ContractError("SEARCH_PROJECTION_PENDING", "Tag resource lifecycle changed", 503)
        documents.append(resource_document(item["reference"], source_sequence=source_sequence, annotation=snapshot))
        # Whole page is accepted or rejected, never partially published.
        if len(json.dumps(documents, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")) > 1048576:
            raise ContractError("SEARCH_PROJECTION_PENDING", "Tag page exceeds byte budget", 503)
    # A current locking read, not only the initial repeatable-read snapshot.
    cursor.execute("SELECT revision FROM cf_tag WHERE tag_id=%s FOR UPDATE", (tag_id,))
    current = cursor.fetchone()
    if current != (revision,):
        raise ContractError("SEARCH_FANOUT_CHANGED", "Tag definition changed during projection", 409)
    if clock() >= deadline:
        raise ContractError("SEARCH_PROJECTION_PENDING", "Tag projection deadline exceeded", 503)
    return dict(documents=documents, next_uid=page["next_uid"])
