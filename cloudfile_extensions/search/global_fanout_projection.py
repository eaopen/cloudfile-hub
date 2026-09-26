"""One global system-tag page, projected under each real library source guard."""
import json
import time
from uuid import uuid4

from ..common.errors import ContractError
from ..common.validation import sequence
from .documents import resource_document
from .source import OwnedIndexSource
from .tag_fanout import global_binding_page


def project_global_binding_page(cursor, *, source, tag_id, revision, upper_uid, after, source_sequence, clock=time.monotonic):
    if (not isinstance(source, OwnedIndexSource) or getattr(cursor, "connection", None) is None or
            cursor.connection is source.worker_connection or not callable(clock)):
        raise ValueError("independent owned global SQL scope and actual native sources required")
    sequence(source_sequence)
    savepoint = "cf_global_tag_" + uuid4().hex
    cursor.execute("SAVEPOINT " + savepoint)
    cursor.execute("RELEASE SAVEPOINT " + savepoint)
    # Hold the current definition row until all native/SQL source reads finish.
    cursor.execute("SELECT revision,kind,scope_repo_id FROM cf_tag WHERE tag_id=%s FOR UPDATE", (tag_id,))
    if cursor.fetchone() != (revision, "system", None):
        raise ContractError("SEARCH_FANOUT_CHANGED", "Global tag definition changed", 409)
    deadline = clock() + 20
    page = global_binding_page(cursor, tag_id=tag_id, revision=revision, upper_uid=upper_uid, after=after, limit=100)
    groups, projected, budget = {}, {}, 0
    for item in page["items"]:
        groups.setdefault(item["reference"]["repo_id"], []).append(item)
    for repo, items in groups.items():
        with source.scope(repo) as native_sql:
            for item in items:
                if clock() >= deadline:
                    raise ContractError("SEARCH_PROJECTION_PENDING", "Global tag projection deadline exceeded", 503)
                snapshot = source.read(native_sql, item["reference"])
                if not isinstance(snapshot, dict) or snapshot.get("uid") != item["resource_uid"]:
                    raise ContractError("SEARCH_PROJECTION_PENDING", "Global tag resource lifecycle changed", 503)
                document = resource_document(item["reference"], source_sequence=source_sequence, annotation=snapshot)
                budget += len(json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")) + 1
                if budget + 2 > 1048576:
                    raise ContractError("SEARCH_PROJECTION_PENDING", "Global tag page exceeds byte budget", 503)
                projected[item["resource_uid"]] = document
    if clock() >= deadline:
        raise ContractError("SEARCH_PROJECTION_PENDING", "Global tag projection deadline exceeded", 503)
    return dict(documents=[projected[item["resource_uid"]] for item in page["items"]], next_uid=page["next_uid"])
