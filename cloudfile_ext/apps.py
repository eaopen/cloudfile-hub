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
        self._configure_database()

        from cloudfile_ext.registry import registry

        from cloudfile_ext import (
            base, acl, sso, audit, metadata, search, checkout,
            external_sources, file_actions, fileops,
        )

        for module in (base, acl, sso, audit, metadata, search,
                       checkout, external_sources, file_actions, fileops):
            module.register(registry)

        registry.seal()

    def _configure_database(self):
        """Add the seafile-db connection and the cf_* router.

        Done here rather than in seahub_settings.py because that file is
        imported as a plain module -- seahub's load_local_settings() copies its
        uppercase names afterwards -- so it has no DATABASES dict to extend.
        Writing ``DATABASES['cloudfile'] = ...`` there raises NameError, which
        seahub catches and logs, silently discarding *every* CloudFile setting
        in the file. This runs in the real settings namespace instead.

        A deployment that has not been configured (no CF_DATABASE_NAME) is
        left alone: the baseline ships no cf_* models, so the connection is
        only needed once a capability brings some.
        """
        from django.conf import settings

        name = getattr(settings, 'CF_DATABASE_NAME', '')
        if not name:
            return

        alias = getattr(settings, 'CF_DATABASE_ALIAS', 'cloudfile')
        if alias not in settings.DATABASES:
            settings.DATABASES[alias] = {
                'ENGINE': 'django.db.backends.mysql',
                'NAME': name,
                'USER': getattr(settings, 'CF_DATABASE_USER', ''),
                'PASSWORD': getattr(settings, 'CF_DATABASE_PASSWORD', ''),
                'HOST': getattr(settings, 'CF_DATABASE_HOST', ''),
                'PORT': getattr(settings, 'CF_DATABASE_PORT', '3306'),
                'OPTIONS': {'charset': 'utf8mb4'},
                'TIME_ZONE': None,
                'CONN_MAX_AGE': 0,
                'CONN_HEALTH_CHECKS': False,
                'AUTOCOMMIT': True,
                'ATOMIC_REQUESTS': False,
                'TEST': {},
            }

        router = 'cloudfile_ext.db_router.CloudFileRouter'
        if router not in settings.DATABASE_ROUTERS:
            settings.DATABASE_ROUTERS = list(settings.DATABASE_ROUTERS) + [router]
