"""Permanent physical index identities; retirement never frees an index name.

This registry is not publication readiness or an active-index pointer. A caller
must hold its SQL transaction while using require_dispatch; asynchronous writes
already accepted by Meilisearch remain isolated in the old physical index.
"""
import re
from contextlib import contextmanager

from ..common.errors import ContractError


class SearchGenerationStore:
    def __init__(self, connection):
        if not connection.get_autocommit():
            raise ValueError("dedicated autocommit connection required")
        self.connection = connection

    @staticmethod
    def _identity(generation, index):
        if (not isinstance(generation, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", generation) or
                not isinstance(index, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", index)):
            raise ValueError("fixed bounded generation and physical index required")

    @contextmanager
    def _transaction(self):
        self.connection.begin()
        try:
            with self.connection.cursor() as sql:
                yield sql
            self.connection.commit()
        finally:
            self.connection.rollback()

    def register(self, generation, index):
        self._identity(generation, index)
        with self._transaction() as sql:
            # Unique keys serialize concurrent registration. The no-op duplicate
            # update cannot rebind either identity or revive a retired row.
            sql.execute("INSERT INTO cf_search_generation(generation,index_uid,state,created_at,updated_at) VALUES(%s,%s,'building',UTC_TIMESTAMP(6),UTC_TIMESTAMP(6)) ON DUPLICATE KEY UPDATE generation=generation", (generation, index))
            sql.execute("SELECT index_uid,state FROM cf_search_generation WHERE generation=%s FOR UPDATE", (generation,))
            row = sql.fetchone()
            if row is None or row[0] != index or row[1] not in ("building", "retired"):
                raise ContractError("SEARCH_GENERATION_CONFLICT", "Physical index identity cannot be reused", 409)
            return row[1]

    def require_dispatch(self, sql, generation, index):
        self._identity(generation, index)
        if sql.connection is not self.connection:
            raise ValueError("owned generation transaction required")
        # SAVEPOINT rejects calls outside a transaction on MySQL. Never start
        # or commit the caller's transaction, and retain the row lock on return.
        sql.execute("SAVEPOINT cf_search_generation_guard")
        sql.execute("RELEASE SAVEPOINT cf_search_generation_guard")
        sql.execute("SELECT index_uid,state FROM cf_search_generation WHERE generation=%s FOR UPDATE", (generation,))
        if sql.fetchone() != (index, "building"):
            raise ContractError("SEARCH_GENERATION_RETIRED", "Search generation cannot accept dispatch", 409)

    def retire(self, generation, index):
        self._identity(generation, index)
        with self._transaction() as sql:
            sql.execute("SELECT index_uid,state FROM cf_search_generation WHERE generation=%s FOR UPDATE", (generation,))
            row = sql.fetchone()
            if row is None or row[0] != index or row[1] not in ("building", "retired"):
                raise ContractError("SEARCH_GENERATION_CONFLICT", "Search generation identity is not current", 409)
            if row[1] == "building":
                sql.execute("UPDATE cf_search_generation SET state='retired',updated_at=UTC_TIMESTAMP(6) WHERE generation=%s AND index_uid=%s AND state='building'", (generation, index))
