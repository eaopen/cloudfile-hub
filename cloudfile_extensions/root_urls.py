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
        if name in RESERVED_DOMAINS:
            raise ImproperlyConfigured("deployment extension cannot replace a core CloudFile domain")
        if not isinstance(module, str) or not URLCONF_RE.fullmatch(module):
            raise ImproperlyConfigured(f"invalid CloudFile extension URLConf: {module!r}")
        result.append((name, module))
    return result


urlpatterns = [
    re_path(r"^api/v2.1/cloudfile/", include("cloudfile_extensions.urls")),
]
if (getattr(settings, "CLOUDFILE_AUTHORIZATION_ENABLED", False) is False
        and getattr(settings, "CF_ENABLE_DIR_ACL", False) is True):
    from .legacy_compat import LegacyEffectivePermission
    urlpatterns.append(re_path(
        r"^api/v2.1/cloudfile/extensions/authorization/v1/effective-permission/$",
        LegacyEffectivePermission.as_view(), name="cloudfile-legacy-effective-permission"))
if getattr(settings, "CLOUDFILE_OIDC_ENABLED", False):
    urlpatterns.append(re_path(r"^api/v2.1/cloudfile/extensions/identity/v1/",
        include("cloudfile_extensions.identity.urls")))
if getattr(settings, "CLOUDFILE_AUTHORIZATION_ENABLED", False):
    urlpatterns.append(re_path(r"^api/v2.1/cloudfile/extensions/authorization/",
        include("cloudfile_extensions.authorization.urls")))
if getattr(settings, "CLOUDFILE_ANNOTATIONS_ENABLED", False):
    urlpatterns.append(re_path(r"^api/v2.1/cloudfile/extensions/annotations/",
        include("cloudfile_extensions.resources.urls")))
if getattr(settings, "CLOUDFILE_LOCAL_EDIT_ENABLED", False):
    urlpatterns.append(re_path(r"^api/v2.1/cloudfile/extensions/local-edit/",
        include("cloudfile_extensions.local_edit.urls")))
if getattr(settings, "CLOUDFILE_TRANSFER_ENABLED", False):
    urlpatterns.append(re_path(r"^api/v2.1/cloudfile/extensions/transfer/",
        include("cloudfile_extensions.transfer.urls")))
if getattr(settings, "CLOUDFILE_AUDIT_QUERY_ENABLED", False):
    urlpatterns.append(re_path(r"^api/v2.1/cloudfile/extensions/audit/",
        include("cloudfile_extensions.events.urls")))
urlpatterns.extend(
    re_path(rf"^api/v2.1/cloudfile/extensions/{name}/", include(module))
    for name, module in _extension_urlconfs()
)
urlpatterns.append(re_path(r"", include("seahub.urls")))
