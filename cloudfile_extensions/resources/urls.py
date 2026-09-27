"""Explicit v0.3 annotations URLs with late worker-owned service resolution."""
from ..authorization.gunicorn import resource_service
from .routes import resource_routes

urlpatterns = resource_routes(service_factory=resource_service)

# Default closed: only the explicitly configured provider may maintain sources.
from django.conf import settings
from django.urls import path
from .provider_http import SystemTagProviderView

if getattr(settings, 'CLOUDFILE_SYSTEM_TAG_PROVIDER_ENABLED', False) is True:
    urlpatterns.append(path('v1/resources/system-tags/', SystemTagProviderView.as_view(), name='resource-system-tags'))
