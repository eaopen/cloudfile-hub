"""Owned authenticated search assembly; mandatory real response protection."""
from contextlib import contextmanager

from ..common.errors import invalid
from ..resources.paths import resource_ref
from ..resources.runtime import ResourceServiceFactory
from .cursor import SearchCursorStore
from .generations import SearchGenerationStore
from .meilisearch import MeilisearchCandidates
from .publication_reader import SearchPublicationReader
from .service import ResourceSearchService


class GuardedSearchRequest:
    def __init__(self, service, response_scope):
        if not isinstance(service, ResourceSearchService) or not callable(response_scope):
            raise ValueError("actual search service and response guard required")
        self.service, self.response_scope = service, response_scope

    @contextmanager
    def response(self, body):
        if not isinstance(body, dict) or "repo_id" not in body:
            raise invalid("Search library is required")
        repo = resource_ref(dict(repo_id=body["repo_id"], path="/", kind="dir"))["repo_id"]
        authority = self.service.resources.read_authority
        # Refresh before entering the final scope; refresh can publish native
        # membership changes and cannot run while holding its own effect guard.
        authority.preparation.prepare(authority.actor)
        # Provider must protect native identity/subject/policy/lifecycle and
        # publication changes through serialization, and assert on exit. It
        # must coordinate with producers without blocking fresh version reads
        # on a row lock held by another connection. A boolean is not a scope.
        with self.response_scope(self.service.resources, repo):
            yield self.service.query(body)


class SearchQueryFactory:
    def __init__(self, *, resources, connection_factory, redis_scope, response_scope,
                 endpoint, index, read_key, generation, cursor_secret):
        if (not isinstance(resources, ResourceServiceFactory) or not callable(connection_factory) or
                not callable(redis_scope) or not callable(response_scope) or
                not isinstance(cursor_secret, bytes) or len(cursor_secret) < 32):
            raise ValueError("owned resource/SQL/Redis runtime and real response guard required")
        SearchGenerationStore._identity(generation, index)
        self.backend = MeilisearchCandidates(endpoint=endpoint, index=index, key=read_key)
        self.versions = SearchPublicationReader(connection_factory=connection_factory,
            generation=generation, index=index)
        self.resources, self.redis_scope = resources, redis_scope
        self.response_scope, self.secret = response_scope, cursor_secret

    @contextmanager
    def __call__(self, request, request_id):
        # The actual resource factory authenticates the native session and
        # expected business subject before acquiring any cursor Redis resource.
        with self.resources(request, request_id) as resources:
            with self.redis_scope() as redis:
                service = ResourceSearchService(resources, self.backend,
                    SearchCursorStore(redis, secret=self.secret), version_reader=self.versions)
                yield GuardedSearchRequest(service, self.response_scope)
