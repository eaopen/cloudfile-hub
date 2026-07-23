# -*- coding: utf-8 -*-
from django.apps import AppConfig


class CloudFileConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'cloudfile_ext'
    verbose_name = 'CloudFile extensions'

    def ready(self):
        """Wire up every enabled capability, then close the registry.

        Each submodule's ``register()`` is responsible for checking its own
        CF_ENABLE_* switch, so that the set of switches consulted stays next to
        the code they gate.
        """
        from cloudfile_ext.registry import registry

        from cloudfile_ext import (
            base, acl, sso, audit, metadata, search, office, checkout,
            external_sources,
        )

        for module in (base, acl, sso, audit, metadata, search, office,
                       checkout, external_sources):
            module.register(registry)

        registry.seal()
