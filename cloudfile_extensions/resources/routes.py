"""Explicit route assembly, not an automatically loaded URLConf.

Release must satisfy native lifecycle/data-plane gates before mounting beneath
the core annotations domain. This changes no public capability or feature flag.
"""
from django.urls import path

from .http import (ResourceResolveView, ResourceAttributesView, ResourceUserTagsView,
    ResourceUserTagValuesView, UserTagCatalogView, UserTagDefinitionView, ResourceBatchView)


def resource_routes(*, service_factory):
    if not callable(service_factory):
        raise ValueError("trusted owned resource service factory required")
    return [
        path("v1/batch/", ResourceBatchView.as_view(service_factory=service_factory), name="resource-batch"),
        path("v1/resources/resolve/", ResourceResolveView.as_view(service_factory=service_factory), name="resource-resolve"),
        path("v1/resources/", ResourceAttributesView.as_view(service_factory=service_factory), name="resource-write"),
        path("v1/resources/user-tags/", ResourceUserTagsView.as_view(service_factory=service_factory), name="resource-user-tags"),
        path("v1/resources/user-tag-values/", ResourceUserTagValuesView.as_view(service_factory=service_factory), name="resource-user-tag-values"),
        path("v1/tags/", UserTagCatalogView.as_view(service_factory=service_factory), name="user-tag-catalog"),
        path("v1/tags/update/", UserTagDefinitionView.as_view(service_factory=service_factory), name="user-tag-update"),
    ]
