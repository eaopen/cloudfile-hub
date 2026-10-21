"""Explicit P0 delegated transfer routes backed by the post-fork policy host."""

from django.urls import include, path

from ..identity.delegated_read_gunicorn import delegated_read_factory
from ..identity.delegated_read_http import DelegatedReadTicketView


urlpatterns = [
    path("v1/", include([
        path("delegated-read-tickets/",
            DelegatedReadTicketView.as_view(service_factory=delegated_read_factory),
            name="cloudfile-delegated-read-ticket"),
    ])),
]
