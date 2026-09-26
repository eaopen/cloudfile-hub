"""Durable verified logout intake, not notification execution or HTTP enablement."""
import hashlib

from ..common.errors import ContractError
from ..jobs.store import JobStore, canonical
from ..schema.runner import SchemaRunner
from .logout_token import LogoutTokenValidator
from .session_index import OIDCSessionIndex


class BackchannelJobs:
    KIND = "identity.logout"

    def __init__(self, store, validator):
        if not isinstance(store, JobStore) or not isinstance(validator, LogoutTokenValidator):
            raise ValueError("actual durable job store and signed notification validator required")
        SchemaRunner(store.connection).require_current()
        self.store, self.validator = store, validator
        config = validator.config
        digest = hashlib.sha256(canonical([config.issuer, config.client_id]).encode()).hexdigest()
        self.actor = "oidc." + digest
        self.provider = "cf_oidc_" + digest[:24]
        self.index = OIDCSessionIndex(store.connection, issuer=config.issuer, client_id=config.client_id)

    def submit(self, token):
        notification = self.validator.validate(token)
        request = dict(issuer=notification.issuer, client_id=notification.client_id,
            jti=notification.jti, subject=notification.subject, session_id=notification.session_id,
            issued_at=notification.issued_at, expires_at=notification.expires_at)
        key = hashlib.sha256(notification.jti.encode()).hexdigest()
        def authorize(cursor):
            # Key lookup, SQL locks and schema checks can take time after JWT
            # verification. Reject expiration before insertion or replay.
            if notification.expires_at <= self.validator.clock():
                raise ContractError("AUTHENTICATION_REQUIRED", "Logout notification expired before acceptance", 401)
            # Shares the provider scope lock and acceptance transaction with
            # the durable job. Older notifications can never lower the fence.
            self.index.fence(cursor, notification)
            return True
        return self.store.submit(actor=self.actor, actor_kind="service", kind=self.KIND,
            scope=dict(type="provider", provider=self.provider, external_id=self.provider),
            request=request, idempotency_key=key, authorize_transaction=authorize)
