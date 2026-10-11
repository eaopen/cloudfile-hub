"""Late post-fork local-edit route adapters.

URL construction must not create SQL, Redis or native runtime state in a
preload master. These typed proxies resolve the worker-owned PolicyHost only
while handling an actual request.
"""
from ..authorization import gunicorn as policy_host
from .agent_runtime import AgentClaimRuntime
from .device_runtime import DeviceManagementFactory
from .read_ticket import AgentReadTicketIssuer
from .session_runtime import LocalSessionFactory


class PostForkLocalSessionFactory(LocalSessionFactory):
    def __init__(self):
        pass

    def __call__(self, request, request_id):
        return policy_host.local_session_service(request, request_id)


class PostForkDeviceManagementFactory(DeviceManagementFactory):
    def __init__(self):
        pass

    def __call__(self, request, request_id):
        return policy_host.local_device_service(request, request_id)


class PostForkAgentClaimRuntime(AgentClaimRuntime):
    def __init__(self):
        pass

    def challenge(self, value, request_id):
        return policy_host.local_agent_call("challenge", value, request_id)

    def claim(self, value, request_id):
        return policy_host.local_agent_call("claim", value, request_id)

    def read_challenge(self, value, request_id):
        return policy_host.local_agent_call("read_challenge", value, request_id)

    def renew_challenge(self, value, request_id):
        return policy_host.local_agent_call("renew_challenge", value, request_id)

    def cancel_challenge(self, value, request_id):
        return policy_host.local_agent_call("cancel_challenge", value, request_id)

    def renew(self, value, request_id):
        return policy_host.local_agent_call("renew", value, request_id)

    def cancel(self, value, request_id):
        return policy_host.local_agent_call("cancel", value, request_id)

    def commit_challenge(self, value, request_id):
        return policy_host.local_agent_call("commit_challenge", value, request_id)

    def commit_authorize(self, value, request_id):
        return policy_host.local_agent_call("commit_authorize", value, request_id)


    def commit_upload_authorize(self, value, request_id):
        return policy_host.local_agent_call("commit_upload_authorize", value, request_id)

    def commit_status_challenge(self, value, request_id):
        return policy_host.local_agent_call("commit_status_challenge", value, request_id)

    def commit_status(self, value, request_id):
        return policy_host.local_agent_call("commit_status", value, request_id)

    def upload_grant(self, value, request_id):
        return policy_host.local_agent_call("upload_grant", value, request_id)

    def upload_receipt(self, value, request_id):
        return policy_host.local_agent_call("upload_receipt", value, request_id)


class PostForkAgentReadTicketIssuer(AgentReadTicketIssuer):
    def issue(self, value, request_id):
        return policy_host.local_read_ticket(value, request_id)


local_session_factory = PostForkLocalSessionFactory()
local_device_factory = PostForkDeviceManagementFactory()
local_agent_runtime = PostForkAgentClaimRuntime()
local_read_issuer = PostForkAgentReadTicketIssuer(local_agent_runtime)
