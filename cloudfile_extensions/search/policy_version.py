"""Conservative durable change token; not a cached permission or native proof."""
import hashlib
from uuid import UUID

from ..schema.runner import SchemaRunner
from .meilisearch import unavailable


def change_token(repo_id, row):
    """Bind both indexed stream watermarks without scanning rules or payloads."""
    if (row is None or len(row) != 2 or
            any(type(value) is not int or not 0 <= value <= 2 ** 64 - 1 for value in row)):
        raise ValueError("valid durable event watermarks required")
    return hashlib.sha256(("cf.search.policy-watermark.v1\n" + repo_id + "\n" +
        str(row[0]) + "\n" + str(row[1])).encode("ascii")).hexdigest()


class SearchPolicyVersionReader:
    """One fresh SQL read of repository and global committed change boundaries.

    Any durable event invalidates cursors conservatively, including access
    audit facts. This is deliberately not a selective ACL revision projection.
    It requires all relevant native mutations to publish durable facts; final
    CE/C checks and producer/response guards remain mandatory. Event retention
    must preserve stream boundaries while cursors can still be alive.
    """
    def __init__(self, connection_factory):
        if not callable(connection_factory):
            raise ValueError("fresh owned SQL connection factory required")
        self.connection_factory = connection_factory

    def __call__(self, repo_id):
        connection = None
        try:
            repo = str(UUID(repo_id))
            if repo != repo_id:
                raise ValueError()
            connection = self.connection_factory()
            if not connection.get_autocommit():
                connection = None
                raise ValueError()
            SchemaRunner(connection).require_current()
            with connection.cursor() as sql:
                # A single statement observes both streams in the same read
                # view. FORCE INDEX avoids a library-wide or payload scan.
                sql.execute("SELECT COALESCE((SELECT MAX(sequence) FROM cf_event_outbox FORCE INDEX(stream_sequence) WHERE stream=%s),0),COALESCE((SELECT MAX(sequence) FROM cf_event_outbox FORCE INDEX(stream_sequence) WHERE stream='security'),0)", ("repo." + repo,))
                return change_token(repo, sql.fetchone())
        except Exception:
            raise unavailable() from None
        finally:
            if connection is not None:
                try:
                    connection.rollback()
                finally:
                    connection.close()
