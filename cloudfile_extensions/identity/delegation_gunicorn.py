"""Typed late post-fork adapter for login-service delegation issuance."""

from ..authorization import gunicorn as policy_host
from .delegation_issue import UserDelegationIssueFactory


class PostForkDelegationIssueFactory(UserDelegationIssueFactory):
    def __init__(self):
        # The actual validated factory is owned by the post-fork PolicyHost.
        pass

    def __call__(self, request, request_id, user_id):
        return policy_host.delegation_issue_service(request, request_id, user_id)


delegation_issue_factory = PostForkDelegationIssueFactory()
