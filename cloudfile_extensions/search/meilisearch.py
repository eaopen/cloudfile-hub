"""Bounded private candidate retrieval, not a public authorized query service."""
import json
import re
import time
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from ..common.errors import ContractError
from ..resources.paths import normalize_path, resource_ref


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


def unavailable():
    return ContractError("SEARCH_UNAVAILABLE", "Resource search is unavailable", 503)


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


class MeilisearchCandidates:
    """Fixed server-owned endpoint/key/index. No browser-supplied filter syntax."""
    def __init__(self, *, endpoint, index, key, clock=time.monotonic):
        parsed = urlsplit(endpoint)
        if (parsed.scheme not in ("https", "http") or not parsed.hostname or parsed.username or
                parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/") or
                not isinstance(index, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", index) or
                not isinstance(key, str) or not re.fullmatch(r"[\x21-\x7e]{1,512}", key)):
            raise ValueError("trusted Meilisearch configuration required")
        # HTTP is only for the explicitly configured private Docker network.
        self.url = endpoint.rstrip("/") + "/indexes/" + index + "/search"
        self.key, self.clock = key, clock
        self.opener = build_opener(ProxyHandler({}), _NoRedirect())

    def page(self, *, q, repo_id, path='/', kind=None, offset=0, limit=100, tag_ids=()):
        try:
            if (not isinstance(q, str) or not q.strip() or len(q) > 512 or
                    type(offset) is not int or not 0 <= offset <= 10000 or
                    type(limit) is not int or not 1 <= limit <= 100 or
                    not isinstance(tag_ids, (list, tuple)) or len(tag_ids) > 32 or kind not in (None, 'file', 'dir')):
                raise ValueError()
            path = normalize_path(path, 'dir')
            if len(path.encode('utf-8')) > 4096:
                raise ValueError()
            ref = resource_ref(dict(repo_id=repo_id, path="/", kind="dir"))
            from uuid import UUID
            tags = [str(UUID(tag)) for tag in tag_ids]
            filters = ["repo_id = " + json.dumps(ref["repo_id"])]
            # Apply directory scope before ranking/pagination. Filtering a
            # whole-library page afterwards wastes candidates and hides hits.
            if path != '/':
                filters.append('dirs = ' + json.dumps(path, ensure_ascii=False))
            if kind is not None:
                filters.append('kind = ' + json.dumps(kind))
            filters.extend("tag_ids = " + json.dumps(tag) for tag in tags)
            payload = json.dumps(dict(q=q, offset=offset, limit=limit, filter=filters,
                attributesToRetrieve=["repo_id", "path", "kind"]), ensure_ascii=False).encode("utf-8")
        except (ValueError, TypeError, AttributeError, UnicodeError, ContractError):
            raise ContractError("INVALID_REQUEST", "Invalid resource search", 400) from None
        deadline = self.clock() + 5
        try:
            request = Request(self.url, data=payload, method="POST", headers={
                "Authorization": "Bearer " + self.key, "Content-Type": "application/json",
                "Accept": "application/json", "Accept-Encoding": "identity"})
            with self.opener.open(request, timeout=5) as response:
                if (response.status != 200 or response.headers.get_content_type() != "application/json" or
                        response.headers.get("Content-Encoding", "identity") != "identity"):
                    raise ValueError()
                raw = bytearray()
                while True:
                    if self.clock() >= deadline:
                        raise ValueError()
                    chunk = response.read(8192)
                    if not chunk:
                        break
                    raw.extend(chunk)
                    if len(raw) > 1048576:
                        raise ValueError()
            document = json.loads(raw.decode("utf-8"), object_pairs_hook=_object)
            if self.clock() >= deadline or not isinstance(document, dict) or not isinstance(document.get("hits"), list) or len(document["hits"]) > limit:
                raise ValueError()
            candidates = []
            for hit in document["hits"]:
                candidate = resource_ref(hit)
                if (candidate["repo_id"] != ref["repo_id"] or len(candidate["path"].encode("utf-8")) > 4096 or
                        (path != '/' and not candidate['path'].startswith(path + '/')) or
                        (kind is not None and candidate['kind'] != kind)):
                    raise ValueError()
                candidates.append(candidate)
            # Never return estimatedTotalHits/facets/highlight or index-provided grants.
            return {"references": candidates, "next_offset": offset + len(candidates) if len(candidates) == limit else None}
        except Exception:
            raise unavailable() from None
