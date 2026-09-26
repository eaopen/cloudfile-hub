"""Explicit preparation routes; not installed in the root URLConf."""
from django.urls import path

from .http import MigrationJobView
from .runtime import MigrationJobFactory


def migration_routes(*, service_factory):
    if not isinstance(service_factory, MigrationJobFactory):
        raise ValueError("actual owned migration job factory required")
    return [path("v1/" + operation + "/", MigrationJobView.as_view(
        service_factory=service_factory, operation=operation), name="migration-" + operation)
        for operation in sorted(service_factory.operations | {"status"})]
