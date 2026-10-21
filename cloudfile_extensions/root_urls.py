"""Compose CloudFile and deployment-provided extensions with upstream Seahub."""

import re

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.urls import include, re_path

from .registry import RESERVED_DOMAINS


URLCONF_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")
EXTENSION_NAME_RE = re.compile(r"^[a-z][a-z0-9-]*$")


def _extension_urlconfs():
    configured = getattr(settings, "CLOUDFILE_EXTENSION_URLCONFS", {})
    if not isinstance(configured, dict):
        raise ImproperlyConfigured("CLOUDFILE_EXTENSION_URLCONFS must be a mapping")

    result = []
    for name, module in sorted(configured.items()):
        if not isinstance(name, str) or not EXTENSION_NAME_RE.fullmatch(name):
            raise ImproperlyConfigured(f"invalid CloudFile extension name: {name!r}")
        if name == 'local-edit':
            raise ImproperlyConfigured(
                'legacy local-edit Session/Device routes are retired; use V2 /api/v2.1/cloudfile/edit/v1/open/')
        if name in RESERVED_DOMAINS:
            raise ImproperlyConfigured("deployment extension cannot replace a core CloudFile domain")
        if not isinstance(module, str) or not URLCONF_RE.fullmatch(module):
            raise ImproperlyConfigured(f"invalid CloudFile extension URLConf: {module!r}")
        result.append((name, module))
    return result


# Current V2 routes are registered by seahub.urls. Do not mount the historical
# Resource/Intent control plane here: it requires the retired migration ledger
# and would turn a valid four-table installation into an SQL failure on use.
# Keep native compatibility reads on V2 Authority; legacy policy readers must
# not be reached through an old URL alias either.
from .library_configuration import LibraryConfiguration
from .authorization.native_http import NativeRepoView
from cloudfile_ext.v2.acl_http import EffectivePermission, SharedDirectories, DirectoryEntries
from .authorization.native_file_http import NativeFileView

urlpatterns = [
    re_path(r"^api/v2.1/cloudfile/libraries/(?P<repo_id>[-0-9a-f]{36})/configuration/$",
        LibraryConfiguration.as_view()),
    re_path(r"^api2/repos/(?P<repo_id>[-0-9a-f]{36})/file/$", NativeFileView.as_view(), name="native-policy-file"),
    re_path(r"^api/v2.1/repos/(?P<repo_id>[-0-9a-f]{36})/$", NativeRepoView.as_view(), name="native-policy-repo"),
    re_path(r"^api/v2.1/cloudfile/extensions/authorization/v1/effective-permission/$",
        EffectivePermission.as_view(), name="native-effective-permission"),
    re_path(r"^api/v2.1/cloudfile/extensions/authorization/v1/shared-directories/$",
        SharedDirectories.as_view(), name="shared-directories"),
    re_path(r"^api/v2.1/cloudfile/extensions/authorization/v1/directory-entries/$",
        DirectoryEntries.as_view(), name="directory-entries"),
]
urlpatterns.extend(
    re_path(rf"^api/v2.1/cloudfile/extensions/{name}/", include(module))
    for name, module in _extension_urlconfs()
)
urlpatterns.append(re_path(r"", include("seahub.urls")))
