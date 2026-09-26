"""Explicit core locks URL assembly; no import-time mounting or activation.

The release assembler must first prove all native mutation entry guards. A
factory's existence proves wiring only, not those release gates.
"""
from django.urls import path

from .http import FileLockView
from .runtime import FileLockFactory


def lock_routes(*, service_factory):
    if not isinstance(service_factory, FileLockFactory):
        raise ValueError("actual owned file lock factory required")
    return [path("v1/" + operation + "/", FileLockView.as_view(
        service_factory=service_factory, operation=operation), name="file-lock-" + operation)
        for operation in ("status", "acquire", "renew", "release", "force-release")]
