from django.urls import path, re_path

from .api import CapabilitiesView
from .library_configuration import LibraryConfiguration
from .library_shares import LibrarySharesDesired
from .directory.sync_http import DirectorySync


app_name = "cloudfile_extensions"

urlpatterns = [
    path("capabilities/", CapabilitiesView.as_view(), name="capabilities"),
    path("directory/sync/", DirectorySync.as_view(), name="directory-sync"),
    re_path(r"^libraries/(?P<repo_id>[-0-9a-f]{36})/configuration/$",
            LibraryConfiguration.as_view(), name="library-configuration"),
    re_path(r"^libraries/(?P<repo_id>[-0-9a-f]{36})/shares/desired/$",
            LibrarySharesDesired.as_view(), name="library-shares-desired"),
]
