"""Explicit lease service assembly; no routes or capability enablement."""
from contextlib import contextmanager

from ..common.validation import identifier
from ..resources.runtime import ResourceServiceFactory
from .service import FileLockService


class FileLockFactory:
    def __init__(self, *, resources, holder_reader, version_reader):
        if (not isinstance(resources, ResourceServiceFactory) or not callable(holder_reader) or
                not callable(version_reader)):
            raise ValueError("actual resource factory and trusted session/version readers required")
        self.resources, self.holder_reader, self.version_reader = resources, holder_reader, version_reader

    @contextmanager
    def __call__(self, request, request_id):
        with self.resources(request, request_id) as resources:
            # This provider resolves the authenticated native session/device;
            # it must not return a browser body/header holder or only userId.
            # Two sessions of one employee are distinct holders.
            holder = self.holder_reader(request, resources)
            identifier(holder, maximum=128)
            yield FileLockService(resources, holder=holder, version_reader=self.version_reader)
