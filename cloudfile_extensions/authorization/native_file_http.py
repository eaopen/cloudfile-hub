"""Preserve Etech's existing CE file API while replacing its read authority."""
from seahub.api2.views import FileView

from .native_read import enabled, response
from .native_transfer import download_url


class NativeFileView(FileView):
    def get(self, request, repo_id, format=None):
        if not enabled():
            return super().get(request, repo_id, format=format)
        return response(request, lambda current: download_url(request, current, repo_id))
