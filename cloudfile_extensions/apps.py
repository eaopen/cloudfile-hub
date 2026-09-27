from django.apps import AppConfig


class CloudFileExtensionsConfig(AppConfig):
    name = "cloudfile_extensions"
    verbose_name = "CloudFile Extensions"

    def ready(self):
        from django.conf import settings
        if getattr(settings, "CLOUDFILE_OIDC_ENABLED", False) is False:
            return
        from .identity.configuration import configure_oidc_host
        configure_oidc_host(settings)
