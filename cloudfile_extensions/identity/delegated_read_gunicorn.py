"""Typed late post-fork adapter for delegated native read tickets."""

from ..authorization import gunicorn as policy_host
from .delegated_read_ticket import DelegatedReadTicketFactory


class PostForkDelegatedReadTicketFactory(DelegatedReadTicketFactory):
    def __init__(self):
        # The actual validated factory is owned by the post-fork PolicyHost.
        pass

    def __call__(self, request, request_id):
        return policy_host.delegated_read_service(request, request_id)


delegated_read_factory = PostForkDelegatedReadTicketFactory()
