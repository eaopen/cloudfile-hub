from django.urls import path, re_path
from django.conf import settings

from .api import CapabilitiesView
from .library_configuration import LibraryConfiguration
from .library_shares import LibrarySharesDesired
from .directory.sync_http import DirectorySync

if (getattr(settings, 'CLOUDFILE_AUTHORIZATION_ENABLED', False) is False
        and getattr(settings, 'CF_ENABLE_SSO', False) is True):
    from cloudfile_ext.sso.apis import AdminLibrarySharesDesiredView
    library_shares_view = AdminLibrarySharesDesiredView.as_view()
else:
    library_shares_view = LibrarySharesDesired.as_view()


app_name = "cloudfile_extensions"

urlpatterns = [
    path("capabilities/", CapabilitiesView.as_view(), name="capabilities"),
    path("directory/sync/", DirectorySync.as_view(), name="directory-sync"),
    re_path(r"^libraries/(?P<repo_id>[-0-9a-f]{36})/configuration/$",
            LibraryConfiguration.as_view(), name="library-configuration"),
    re_path(r"^libraries/(?P<repo_id>[-0-9a-f]{36})/shares/desired/$",
            library_shares_view, name="library-shares-desired"),
]
