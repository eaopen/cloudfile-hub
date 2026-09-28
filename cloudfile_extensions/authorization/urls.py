"""Explicit P0 authorization routes backed only by the post-fork policy host."""

from django.urls import include, path

from ..directory.refresh_http import machine_user_refresh_routes
from ..directory.self_http import own_context_routes
from ..identity.delegation_gunicorn import delegation_issue_factory
from ..identity.delegation_issue_http import delegation_issue_routes
from .gunicorn import context_service, machine_refresh_service, policy_service
from .http import DirectoryPolicyView, DirectoryEffectiveView, LibraryRulesView


urlpatterns = [
    path("v1/effective-permission/", DirectoryEffectiveView.as_view(service_factory=policy_service), name="directory-policy-effective"),
    path("v1/directory-rules/", DirectoryPolicyView.as_view(service_factory=policy_service), name="directory-policy-list"),
    path("v1/library-rules/", LibraryRulesView.as_view(service_factory=policy_service), name="library-policy-rules"),
    path("v1/directory-rules/<uuid:rule_id>/", DirectoryPolicyView.as_view(service_factory=policy_service), name="directory-policy-item"),
    *own_context_routes(service_factory=context_service),
    *machine_user_refresh_routes(service_factory=machine_refresh_service),
    path("v1/", include(delegation_issue_routes(factory=delegation_issue_factory))),
]
