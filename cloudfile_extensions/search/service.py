"""Request-scoped candidate query with actual resource authorization.

Version reader must be a trusted durable index
and policy-state adapter; a caller-provided version is never accepted.
"""
import time
from uuid import UUID

from ..common.errors import ContractError, invalid
from ..common.validation import object_fields
from ..resources.paths import is_descendant_or_equal, normalize_path
from ..resources.service import ResourceService
from .cursor import SearchCursorStore
from .meilisearch import MeilisearchCandidates, unavailable


class ResourceSearchService:
    def __init__(self, resources, backend, cursors, *, version_reader, clock=time.monotonic):
        if (not isinstance(resources, ResourceService) or not isinstance(backend, MeilisearchCandidates) or
                not isinstance(cursors, SearchCursorStore) or not callable(version_reader)):
            raise ValueError("actual resource/search/cursor adapters required")
        self.resources, self.backend, self.cursors = resources, backend, cursors
        self.version_reader, self.clock = version_reader, clock

    def _versions(self, repo):
        try:
            result = self.version_reader(repo)
            if (not isinstance(result, dict) or set(result) != {"policy_revision", "index_generation", "ready"} or
                    result["ready"] is not True or any(not isinstance(result[name], str) or not result[name] or
                    len(result[name]) > 512 for name in ("policy_revision", "index_generation"))):
                raise ValueError()
            return result
        except Exception:
            raise unavailable() from None

    def query(self, request):
        object_fields(request, ("q", "repo_id"), ("path", "kind", "tag_ids", "limit", "cursor"))
        try:
            q, limit = request["q"], request.get("limit", 50)
            if not isinstance(q, str) or not q.strip() or len(q) > 512 or type(limit) is not int or not 1 <= limit <= 100:
                raise ValueError()
            q.encode("utf-8")
            repo = str(UUID(request["repo_id"]))
            path = normalize_path(request.get("path", "/"), "dir")
            if len(path.encode("utf-8")) > 4096 or request.get("kind") not in (None, "file", "dir"):
                raise ValueError()
            tags = request.get("tag_ids", [])
            if not isinstance(tags, list) or len(tags) > 32:
                raise ValueError()
            tags = sorted(set(str(UUID(tag)) for tag in tags))
        except (ValueError, TypeError, AttributeError, UnicodeError):
            raise invalid("Invalid resource search") from None
        deadline = self.clock() + 20
        authority = self.resources.read_authority
        authority.preparation.prepare(authority.actor)
        current = authority.preparation.contexts.current(authority.actor)
        if current is None:
            raise unavailable()
        versions = self._versions(repo)
        query = dict(q=q, repo_id=repo, path=path, kind=request.get("kind"), tag_ids=tags, limit=limit)
        scope = dict(user_id=authority.actor, context_epoch=current["context_epoch"],
            policy_revision=versions["policy_revision"], index_generation=versions["index_generation"], query=query)
        offset, expiry = (0, None) if request.get("cursor") is None else self.cursors.resolve(request["cursor"], scope=scope)
        candidates = self.backend.page(q=q, repo_id=repo, path=path, kind=query['kind'],
            tag_ids=tags, offset=offset, limit=limit)
        references = [ref for ref in candidates["references"] if is_descendant_or_equal(ref["path"], path) and
            (query["kind"] is None or ref["kind"] == query["kind"])]
        if self.clock() >= deadline:
            raise unavailable()
        # Actual ResourceService performs CE/C read qualification and authoritative
        # lifecycle checks. 403/404 become absent results; runtime errors abort.
        batch = self.resources.batch_resolve(dict(references=references)) if references else dict(items=[])
        current_after = authority.preparation.contexts.current(authority.actor)
        if (current_after is None or current_after["context_epoch"] != scope["context_epoch"] or
                self._versions(repo) != versions or self.clock() >= deadline):
            raise unavailable()
        items = [dict(reference=item["reference"], annotation=item["snapshot"])
            for item in batch["items"] if item["status"] == 200 and
            set(tags).issubset({tag["tag_id"] for tag in item["snapshot"].get("tags", []) if tag.get("enabled") is True})]
        next_offset = candidates["next_offset"]
        cursor = self.cursors.issue(scope=scope, offset=next_offset, expires_at=expiry) if next_offset is not None and next_offset <= 10000 else None
        return dict(items=items, next_cursor=cursor, provider="meilisearch", fallback=False)
