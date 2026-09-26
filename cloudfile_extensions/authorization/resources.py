"""Owned native policy connections; no runtime DDL or automatic reconnect."""
from contextlib import contextmanager

from ..directory.native_state import NativeSubjectState
from ..directory.preparation import SubjectPreparation
from ..directory.project import qualified
from ..directory.provider import DirectoryProvider
from ..jobs.runtime import connect_database
from ..schema.runner import SchemaRunner


class PolicyResources:
    def __init__(self, *, environment, redis, provider_id, directory_factory,
                 native_schema, identity_schema, prefix="cf:subjects:"):
        if not callable(directory_factory):
            raise ValueError("owned directory client factory required")
        # Validate identifiers now; schemas are deployment configuration, not
        # inferred from an authenticated user's organization or request body.
        qualified(native_schema, "EmailUser")
        qualified(identity_schema, "profile_profile")
        self.environment = dict(environment)
        self.redis, self.provider = redis, provider_id
        self.directory_factory = directory_factory
        self.native_schema, self.identity_schema = native_schema, identity_schema
        self.prefix = prefix

    @contextmanager
    def connection(self):
        connection = connect_database(self.environment)
        try:
            # Gap/range absence protection is part of the authority contract.
            # Configure before any effect transaction rather than guessing the
            # server default or weakening checks to accommodate READ COMMITTED.
            with connection.cursor() as cursor:
                cursor.execute("SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            SchemaRunner(connection).require_current()
            yield connection
        finally:
            try:
                connection.rollback()
            finally:
                connection.close()

    @contextmanager
    def state(self):
        with self.connection() as connection:
            yield NativeSubjectState(connection, native_schema=self.native_schema,
                identity_schema=self.identity_schema, provider=self.provider)

    @contextmanager
    def preparation(self, actor, request_id):
        with self.connection() as connection:
            directory = self.directory_factory()
            if not isinstance(directory, DirectoryProvider):
                raise ValueError("real directory provider required")
            try:
                yield SubjectPreparation(connection, self.redis, provider_id=self.provider,
                    directory=directory, native_schema=self.native_schema,
                    identity_schema=self.identity_schema, actor_user_id=actor,
                    request_id=request_id, prefix=self.prefix)
            finally:
                # The directory factory supplies an owned HTTPS session. Redis
                # uses the fixed deployment pool and is not closed per request.
                directory.client.session.close()
