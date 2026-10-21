"""Thin compatibility namespace for the current CE / V2 native routes.

Historical PolicyHost / hosted OIDC / SchemaRunner activation is retired.
Authentication uses native Seahub OAuth/OIDC, while Etech entities and
memberships are projected by cloudfile_ext.v2.
"""
from django.apps import AppConfig


class CloudFileExtensionsConfig(AppConfig):
    name = "cloudfile_extensions"
    verbose_name = "CloudFile Extensions"
