"""Hub observations of explicit transfers, never native transaction receipts."""
from datetime import datetime, timezone
from uuid import uuid4

from ..common.errors import ContractError
from ..events.outbox import EventWriter


def record_transfer(resources, actor, reference, request_id, action, result, *, reason=None, content_version=None):
    fact = dict(event_id=str(uuid4()), occurred_at=datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        request_id=request_id, actor_user_id=actor, actor_kind='user', source='hub',
        action=action, result=result, repo_id=reference['repo_id'], path=reference['path'], resource_kind='file')
    if reason is not None:
        fact['reason'] = reason
    if content_version is not None:
        fact['content_version'] = content_version
    try:
        with resources.connection() as connection:
            connection.begin()
            try:
                with connection.cursor() as cursor:
                    saved = EventWriter().append(cursor, fact)
                connection.commit()
                return saved
            finally:
                connection.rollback()
    except Exception:
        raise ContractError('AUDIT_UNAVAILABLE', 'Transfer audit is unavailable', 503) from None
