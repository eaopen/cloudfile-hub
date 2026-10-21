"""Compatibility route for the CE file API and its current V2 download guard."""
from seahub.api2.views import FileView


class NativeFileView(FileView):
    # FileView already issues V2 path-scoped tickets for current file downloads.
    # Do not shadow it with the retired Directory provider / group projector:
    # Cookie and OIDC sessions must use the same native byte authority.
    pass
