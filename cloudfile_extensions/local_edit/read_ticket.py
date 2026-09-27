"""Device-authenticated single-file ticket issue, no public route or retry.

Native ticket consumption and every transfer block repeat current authority.
This adapter does not enable transfers or accept a client-supplied native user,
path, object, operation, conditions or alternate transport.
"""
from ..common.errors import ContractError
from ..identity.ticket_transport import resolve_and_issue_native_ticket
from .agent_runtime import AgentClaimRuntime
from .session_service import NativeLocalReadConditions


class AgentReadTicketIssuer:
    def __init__(self, runtime):
        if not isinstance(runtime, AgentClaimRuntime):
            raise ValueError("actual owned device runtime required")
        self.runtime = runtime

    def issue(self, value, request_id):
        # This returns only after the authority transaction and directory/SQL
        # resources close. Do not move the RPC into the service effect callback.
        conditions = self.runtime.prepare_native_read(value, request_id)
        if not isinstance(conditions, NativeLocalReadConditions):
            raise ContractError("LOCAL_SESSION_UNAVAILABLE", "Native read authority is unavailable", 503)
        try:
            ticket = resolve_and_issue_native_ticket(conditions.repo_id, conditions.path,
                "download", conditions.native_username, conditions.encoded,
                expected_object_id=conditions.object_id)
        except Exception:
            # A transport timeout may have created a short-lived server ticket.
            # Never replay consumed proof or disclose RPC details/conditions.
            raise ContractError("LOCAL_READ_UNAVAILABLE", "Native local read could not be established", 503) from None
        # Same-origin dedicated guarded endpoint, not legacy /files/{token}.
        # The bearer belongs in a header, never a URL/query/log. This candidate
        # path remains unregistered until deployment/native release gates pass.
        return dict(ticket=ticket, expires_in=60,
            transfer=dict(path="/seafhttp/cloudfile/read", method="GET",
                authorization="Bearer", redirects=False, resume=False),
            file=dict(extension=conditions.extension, local_open_type=conditions.local_open_type,
                mode=conditions.mode, base_version=conditions.object_id))
