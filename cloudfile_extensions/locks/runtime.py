"""Explicit lease service assembly; no routes or capability enablement."""
from contextlib import contextmanager
import hmac
import json

from ..common.validation import identifier
from ..resources.runtime import ResourceServiceFactory
from .service import FileLockService
from .authority import LockManagementAuthority


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
            identifier(holder, maximum=512)
            # Never expose a native session key or device credential as a public
            # holder ID. Domain-separated HMAC retains stable session isolation.
            holder = hmac.digest(resources.store.secret, json.dumps([
                "cf.lock.holder.v1", resources.write_authority.state.provider,
                resources.write_authority.actor, holder], ensure_ascii=False,
                separators=(",", ":")).encode("utf-8"), "sha256").hex()
            management = LockManagementAuthority(resources.read_authority.preparation,
                self.resources.core, request_id=request_id, cloud_mode=self.resources.cloud_mode)
            try:
                yield FileLockService(resources, holder=holder, version_reader=self.version_reader, management=management)
            finally:
                management.epoch = None
                management.current_subject = None
                management.is_owner = False
                management.effective_access = None
