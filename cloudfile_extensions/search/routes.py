"""Explicit core search URL assembly; not an automatically loaded URLConf.

Publication, current response guards and release evidence remain mandatory.
This helper changes neither capability registration nor deployment settings.
"""
from django.urls import path

from .http import ResourceSearchView
from .query_runtime import SearchQueryFactory


def search_routes(*, service_factory):
    if not isinstance(service_factory, SearchQueryFactory):
        raise ValueError("actual owned guarded search factory required")
    return [path("v1/query/", ResourceSearchView.as_view(service_factory=service_factory),
        name="resource-search-query")]
