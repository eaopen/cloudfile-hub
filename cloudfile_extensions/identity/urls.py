"""Opt-in hosted login routes; resource lookup happens only in the worker."""

from django.conf import settings

from ..authorization.gunicorn import login_resources_scope
from .hosted_routes import hosted_login_routes


urlpatterns = hosted_login_routes(resources_scope=login_resources_scope,
    return_path=settings.CLOUDFILE_OIDC_RETURN_PATH,
    backchannel_enabled=getattr(settings, "CLOUDFILE_OIDC_BACKCHANNEL_ENABLED", False),
    read_tickets_enabled=getattr(settings, "CLOUDFILE_TRANSFER_ENABLED", False))
