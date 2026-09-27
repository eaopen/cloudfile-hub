"""Explicit v0.3 annotations URLs with late worker-owned service resolution."""
from ..authorization.gunicorn import resource_service
from .routes import resource_routes

urlpatterns = resource_routes(service_factory=resource_service)
