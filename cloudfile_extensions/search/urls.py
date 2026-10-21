"""Default-off post-fork resource search route."""
from django.urls import path

from ..authorization.gunicorn import search_service
from .http import ResourceSearchView

urlpatterns = [path("v1/query/", ResourceSearchView.as_view(service_factory=search_service),
    name="resource-search-query")]
