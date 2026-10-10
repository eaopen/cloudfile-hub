"""Crash-safe checkpoint for the legacy Meilisearch Activity indexer.

The existing cf_search_index_state.detail column stores one task receipt.
Do not treat Meilisearch HTTP 202 as index task completion.
"""
import json


class PendingTaskError(Exception):
    pass


def encode_receipt(cursor, last_id, phase, task_id=None):
    if not isinstance(cursor, int) or not isinstance(last_id, int) or last_id <= cursor:
        raise ValueError("ordered Activity cursor required")
    if phase not in ("upsert", "delete"):
        raise ValueError("unexpected mutation phase")
    if task_id is not None and (type(task_id) is not int or task_id < 0):
        raise ValueError("invalid Meilisearch task id")
    return json.dumps({"cursor": cursor, "last_id": last_id,
                       "phase": phase, "task_id": task_id},
                      separators=(",", ":"), sort_keys=True)


def decode_receipt(status, detail, cursor):
    if status in (None, "ok"):
        return None
    if status not in ("submitting", "submitted", "error"):
        raise PendingTaskError("unknown legacy index checkpoint state")
    try:
        data = json.loads(detail or "")
        if (not isinstance(data, dict) or set(data) !=
                {"cursor", "last_id", "phase", "task_id"} or
                type(data["cursor"]) is not int or data["cursor"] != cursor or
                type(data["last_id"]) is not int or data["last_id"] <= cursor or
                data["phase"] not in ("upsert", "delete") or
                (status == "submitted" and
                 (type(data["task_id"]) is not int or data["task_id"] < 0))):
            raise ValueError()
        return dict(status=status, **data)
    except (ValueError, TypeError, KeyError):
        raise PendingTaskError("invalid persisted legacy Meilisearch receipt") from None


def drive_tasks(state, client, *, name, cursor, last_id, upserts, deletes):
    """One ordered Meili task phase per tick; cursor only advances after success.

    A lost task acceptance response keeps the durable 'submitting' intent and
    requires operator reconciliation rather than blindly repeating the mutation.
    """
    pending = state.get_pending(name)
    if pending:
        if pending["status"] != "submitted":
            raise PendingTaskError("index task is unconfirmed; reconcile before continuing")
        if pending["cursor"] != cursor or pending["last_id"] != last_id:
            raise PendingTaskError("Activity batch changed during task recovery")
        phase = pending["phase"]
        task_id = pending["task_id"]
    else:
        phase = "upsert" if upserts else "delete" if deletes else None
        task_id = None
    if phase is None:
        state.advance(name, last_id, "ok")
        return True

    def dispatch(phase):
        detail = encode_receipt(cursor, last_id, phase)
        state.advance(name, cursor, "submitting", detail)
        # The acceptance response can be lost after Meili accepted the task.
        # Keep 'submitting' to block unsafely repeated submissions.
        if phase == "upsert":
            uid = client.upsert_documents(list(upserts.values()))
        else:
            uid = client.delete_documents(deletes)
        if type(uid) is not int or uid < 0:
            raise PendingTaskError("Meilisearch did not return a valid task id")
        state.advance(name, cursor, "submitted",
                      encode_receipt(cursor, last_id, phase, uid))
        return uid

    if task_id is None:
        task_id = dispatch(phase)
    status = client.task_status(task_id)
    if status in ("enqueued", "processing"):
        return False
    if status != "succeeded":
        state.advance(name, cursor, "error", encode_receipt(cursor, last_id, phase, task_id))
        raise PendingTaskError("Meilisearch task failed or returned invalid status")

    if phase == "upsert" and deletes:
        # Strict phase order. A failure during delete submission remains
        # 'submitting' and never skips the original Activity range.
        task_id = dispatch("delete")
        status = client.task_status(task_id)
        if status in ("enqueued", "processing"):
            return False
        if status != "succeeded":
            state.advance(name, cursor, "error", encode_receipt(cursor, last_id, "delete", task_id))
            raise PendingTaskError("Meilisearch delete task failed; operator reconciliation required")
    state.advance(name, last_id, "ok")
    return True
