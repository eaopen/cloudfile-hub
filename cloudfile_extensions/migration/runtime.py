"""Owned migration preparation API assembly, without native import activation."""
from contextlib import contextmanager

from ..authorization.read import LibraryWideManagementAuthority
from ..resources.runtime import ResourceServiceFactory
from .service import MigrationJobService


class MigrationJobFactory:
    def __init__(self, *, resources, source_ids, enabled_operations=frozenset({"scan"})):
        if (not isinstance(resources, ResourceServiceFactory) or not isinstance(source_ids, frozenset) or
                not source_ids or not isinstance(enabled_operations, frozenset) or not enabled_operations or
                not enabled_operations <= MigrationJobService.operations.keys()):
            raise ValueError("actual resource authentication and explicit registered migration operations required")
        self.resources, self.source_ids, self.operations = resources, source_ids, enabled_operations

    @contextmanager
    def __call__(self, request, request_id):
        with self.resources(request, request_id) as resources:
            management = LibraryWideManagementAuthority(resources.read_authority.preparation,
                self.resources.core, request_id=request_id, cloud_mode=self.resources.cloud_mode)
            try:
                yield MigrationJobService(resources, management, source_ids=self.source_ids,
                    enabled_operations=self.operations)
            finally:
                management.epoch = None
                management.current_subject = None
                management.is_owner = False
                management.effective_access = None
