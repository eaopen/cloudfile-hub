"""P0 contract: Meilisearch HTTP task acceptance does not advance Activity."""

import pytest

from cloudfile_ext.search.task_checkpoint import (
    PendingTaskError, decode_receipt, drive_tasks, encode_receipt,
)
from cloudfile_ext.search.backends.meilisearch import MeilisearchClient, MeilisearchError


class FakeState:
    def __init__(self):
        self.cursor, self.status, self.detail = 0, "ok", ""
        self.history = []

    def get_pending(self, name):
        return decode_receipt(self.status, self.detail, self.cursor)

    def advance(self, name, cursor, status, detail=""):
        self.cursor, self.status, self.detail = cursor, status, detail
        self.history.append((cursor, status))


class FakeClient:
    def __init__(self, *, statuses=("succeeded",), fail_ack=False):
        self.next_uid = 10
        self.statuses = list(statuses)
        self.fail_ack = fail_ack
        self.calls = []

    def upsert_documents(self, payload):
        self.calls.append(("upsert", payload))
        if self.fail_ack:
            raise MeilisearchError("response lost after submission")
        self.next_uid += 1
        return self.next_uid

    def delete_documents(self, payload):
        self.calls.append(("delete", payload))
        self.next_uid += 1
        return self.next_uid

    def task_status(self, uid):
        self.calls.append(("status", uid))
        return self.statuses.pop(0) if self.statuses else "succeeded"


def advance(state, client, upserts=None, deletes=None):
    return drive_tasks(state, client, name="meilisearch", cursor=0,
                       last_id=3, upserts=upserts or {}, deletes=deletes or set())


def test_both_phases_confirm_success_before_advancing():
    state, client = FakeState(), FakeClient()
    assert advance(state, client, {"a": dict(id="a")}, {"deleted"}) is True
    assert state.cursor == 3 and state.status == "ok"
    assert [name for name, _ in client.calls] == ["upsert", "status", "delete", "status"]
    assert state.history == [(0, "submitting"), (0, "submitted"),
                             (0, "submitting"), (0, "submitted"), (3, "ok")]


def test_enqueued_task_recovers_without_redispatch():
    state, client = FakeState(), FakeClient(statuses=["enqueued", "succeeded", "succeeded"])
    payload = {"a": dict(id="a")}
    assert advance(state, client, payload, {"deleted"}) is False
    assert state.cursor == 0 and state.status == "submitted"
    assert advance(state, client, payload, {"deleted"}) is True
    assert len([name for name, _ in client.calls if name == "upsert"]) == 1
    assert state.cursor == 3


def test_delete_task_pending_then_resume():
    state, client = FakeState(), FakeClient(statuses=["succeeded", "processing", "succeeded"])
    assert advance(state, client, {"a": dict(id="a")}, {"deleted"}) is False
    assert state.get_pending("meilisearch")["phase"] == "delete"
    assert advance(state, client, {"a": dict(id="a")}, {"deleted"}) is True
    assert len([name for name, _ in client.calls if name == "delete"]) == 1
    assert state.cursor == 3


def test_failed_task_never_advances_cursor():
    state, client = FakeState(), FakeClient(statuses=["failed"])
    with pytest.raises(PendingTaskError):
        advance(state, client, {"a": dict(id="a")})
    assert state.cursor == 0 and state.status == "error"
    with pytest.raises(PendingTaskError):
        advance(state, client, {"a": dict(id="a")})


def test_unknown_http_acceptance_requires_operator_reconciliation():
    state, client = FakeState(), FakeClient(fail_ack=True)
    with pytest.raises(MeilisearchError):
        advance(state, client, {"a": dict(id="a")})
    assert state.cursor == 0 and state.status == "submitting"
    with pytest.raises(PendingTaskError):
        advance(state, client, {"a": dict(id="a")})
    assert len([name for name, _ in client.calls if name == "upsert"]) == 1


def test_malformed_receipts_fail_closed_and_empty_batch_advances():
    with pytest.raises(PendingTaskError):
        decode_receipt("submitted", '{"cursor":0}', 0)
    state, client = FakeState(), FakeClient()
    assert advance(state, client) is True
    assert state.cursor == 3 and not client.calls


def test_client_validates_exact_async_task_receipts(monkeypatch):
    client = MeilisearchClient("http://localhost:7700")
    monkeypatch.setattr(client, "_call", lambda *args, **kwargs: {"taskUid": 13})
    assert client.upsert_documents([{"id": "1"}]) == 13
    assert client.delete_documents({"1"}) == 13
    with pytest.raises(MeilisearchError):
        client.task_status(13)
    monkeypatch.setattr(client, "_call", lambda *args, **kwargs: {
        "uid": 13, "indexUid": "cloudfile_files", "status": "succeeded"})
    assert client.task_status(13) == "succeeded"
    monkeypatch.setattr(client, "_call", lambda *args, **kwargs: {"taskUid": "13"})
    with pytest.raises(MeilisearchError):
        client.upsert_documents([{"id": "1"}])
