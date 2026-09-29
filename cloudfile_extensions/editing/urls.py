"""Closed by default; mounted only with the trusted editing runtime."""
from ..authorization.gunicorn import editing_service
from .routes import editing_routes

urlpatterns = editing_routes(service_factory=editing_service)
