"""Coherent login routes for an explicit trusted host; never auto-installed."""
from contextlib import contextmanager
from django.urls import path

from .begin_http import login_begin_routes
from .callback_http import login_callback_routes
from .pending_http import PendingStatusView
from .resources import LoginResources


def login_routes(*, resources, return_path="/"):
    if not isinstance(resources, LoginResources):
        raise ValueError("actual owned login resources required")
    @contextmanager
    def pending(request_id):
        with resources.runtime(request_id) as runtime:
            yield runtime.pending
    return (login_begin_routes(resources=resources, return_path=return_path)
        + login_callback_routes(resources=resources)
        + [path("pending/", PendingStatusView.as_view(service_factory=pending),
            name="cloudfile-oidc-pending")])
