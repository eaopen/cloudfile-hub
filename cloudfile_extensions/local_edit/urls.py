"""Explicit local-edit routes; enabled only by trusted deployment settings."""
from .agent_http import agent_claim_routes
from .device_http import device_routes
from .gunicorn import (local_agent_runtime, local_device_factory,
                       local_read_issuer, local_session_factory)
from .session_http import local_session_routes
from .exclusive_http import ExclusiveStartView, ExclusiveAbandonView
from django.urls import path


urlpatterns = [
    path("v1/sessions/start-exclusive/", ExclusiveStartView.as_view(), name="local-session-start-exclusive"),
    path("v1/sessions/abandon-exclusive/", ExclusiveAbandonView.as_view(), name="local-session-abandon-exclusive"),
    *device_routes(service_factory=local_device_factory),
    *local_session_routes(service_factory=local_session_factory),
    *agent_claim_routes(runtime=local_agent_runtime, read_issuer=local_read_issuer),
]
