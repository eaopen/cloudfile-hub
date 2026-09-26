"""Private bounded async index writes. Acceptance is never task completion."""
import json
import re
from urllib.parse import urlsplit
from urllib.request import Request

from .documents import INDEX_SETTINGS, document_key
from .meilisearch import MeilisearchCandidates, _object, unavailable


class MeilisearchTasks(MeilisearchCandidates):
    def __init__(self, **configuration):
        super().__init__(**configuration)
        self.index = configuration["index"]
        self.index_url = self.url.rsplit("/", 1)[0]
        parsed = urlsplit(self.url)
        self.task_url = parsed.scheme + "://" + parsed.netloc + "/tasks/"
        self.indexes_url = parsed.scheme + "://" + parsed.netloc + "/indexes"

    def _request(self, url, *, method, data=None, status):
        try:
            body = None if data is None else json.dumps(data, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
            if body is not None and len(body) > 1048576:
                raise ValueError()
            deadline = self.clock() + 5
            request = Request(url, data=body, method=method, headers={"Authorization": "Bearer " + self.key,
                "Content-Type": "application/json", "Accept": "application/json", "Accept-Encoding": "identity"})
            with self.opener.open(request, timeout=5) as response:
                if response.status != status or response.headers.get_content_type() != "application/json" or response.headers.get("Content-Encoding", "identity") != "identity":
                    raise ValueError()
                raw = response.read(65537)
                if len(raw) > 65536 or self.clock() >= deadline:
                    raise ValueError()
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=_object)
            if not isinstance(value, dict):
                raise ValueError()
            return value
        except Exception:
            raise unavailable() from None

    def _accepted(self, value, task_type):
        if (type(value.get("taskUid")) is not int or not 0 <= value["taskUid"] <= 2 ** 63 - 1 or
                value.get("indexUid") != self.index or value.get("type") != task_type or value.get("status") != "enqueued"):
            raise unavailable()
        return value["taskUid"]

    def replace_documents(self, documents):
        fields = {"id", "repo_id", "path", "kind", "name", "description", "tag_ids", "tag_labels", "tag_codes", "resource_uid", "source_sequence"}
        if not isinstance(documents, list) or not 1 <= len(documents) <= 100:
            raise ValueError("bounded document batch required")
        seen = set()
        for document in documents:
            if (not isinstance(document, dict) or set(document) != fields or
                    document["id"] != document_key({name: document[name] for name in ("repo_id", "path", "kind")}) or document["id"] in seen):
                raise ValueError("trusted unique resource projections required")
            seen.add(document["id"])
        value = self._request(self.index_url + "/documents?primaryKey=id", method="POST", data=documents, status=202)
        return self._accepted(value, "documentAdditionOrUpdate")

    def delete_documents(self, keys):
        if not isinstance(keys, list) or not 1 <= len(keys) <= 100 or any(not isinstance(key, str) or not re.fullmatch(r"[0-9a-f]{64}", key) for key in keys):
            raise ValueError("bounded exact resource keys required")
        value = self._request(self.index_url + "/documents/delete-batch", method="POST", data=keys, status=202)
        return self._accepted(value, "documentDeletion")

    def create_index(self):
        """Explicit fixed physical index; existing-index failure is not success.

        The trusted initialization coordinator must persist intent before this
        call and its receipt afterwards. This method never retries or adopts an
        existing index, and does not mark a generation ready.
        """
        value = self._request(self.indexes_url, method="POST",
            data=dict(uid=self.index, primaryKey="id"), status=202)
        return self._accepted(value, "indexCreation")

    def configure_index(self):
        # No caller-defined settings, raw filters, project attributes or wildcard
        # displayed fields. Copy lists so transport cannot mutate the constants.
        settings = {key: list(values) for key, values in INDEX_SETTINGS.items()}
        value = self._request(self.index_url + "/settings", method="PATCH", data=settings, status=202)
        return self._accepted(value, "settingsUpdate")

    def require_configuration(self):
        """Current physical identity/settings check, not publication proof."""
        identity = self._request(self.index_url, method="GET", status=200)
        if identity.get("uid") != self.index or identity.get("primaryKey") != "id":
            raise unavailable()
        settings = self._request(self.index_url + "/settings", method="GET", status=200)
        for key, expected in INDEX_SETTINGS.items():
            actual = settings.get(key)
            if (not isinstance(actual, list) or any(not isinstance(value, str) for value in actual) or
                    len(actual) != len(expected) or
                    (actual != expected if key == "searchableAttributes" else set(actual) != set(expected))):
                raise unavailable()

    def task_status(self, task_id, *, task_type):
        if type(task_id) is not int or not 0 <= task_id <= 2 ** 63 - 1 or task_type not in ("documentAdditionOrUpdate", "documentDeletion", "indexCreation", "settingsUpdate"):
            raise ValueError("exact persisted task identity required")
        value = self._request(self.task_url + str(task_id), method="GET", status=200)
        if (type(value.get("uid")) is not int or value["uid"] != task_id or value.get("indexUid") != self.index or
                value.get("type") != task_type or value.get("status") not in ("enqueued", "processing", "succeeded", "failed", "canceled")):
            raise unavailable()
        # Do not return raw upstream error/details; failed/canceled never qualify.
        return value["status"]
