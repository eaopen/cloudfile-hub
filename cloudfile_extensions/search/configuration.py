"""Default-off resource search with fixed private endpoint and index identity."""
from ..common.validation import object_fields
from .generations import SearchGenerationStore
from .meilisearch import MeilisearchCandidates
from .tasks import MeilisearchTasks


def validate_config(value):
    object_fields(value, ("endpoint", "index", "generation", "read_key", "write_key", "cursor_secret"))
    SearchGenerationStore._identity(value["generation"], value["index"])
    MeilisearchCandidates(endpoint=value["endpoint"], index=value["index"], key=value["read_key"])
    MeilisearchTasks(endpoint=value["endpoint"], index=value["index"], key=value["write_key"])
    if not isinstance(value["cursor_secret"], bytes) or len(value["cursor_secret"]) < 32:
        raise ValueError("fixed search cursor secret required")
    return dict(value)


def require_configuration(settings):
    enabled = getattr(settings, "CLOUDFILE_RESOURCE_SEARCH_ENABLED", False)
    if type(enabled) is not bool:
        raise ValueError("CLOUDFILE_RESOURCE_SEARCH_ENABLED must be a boolean")
    if not enabled:
        return None
    if (getattr(settings, "CLOUDFILE_OIDC_ENABLED", False) is not True or
            getattr(settings, "CLOUDFILE_AUTHORIZATION_ENABLED", False) is not True or
            not isinstance(getattr(settings, "CLOUDFILE_RESOURCE_SECRET", None), bytes) or
            len(settings.CLOUDFILE_RESOURCE_SECRET) < 32 or
            not callable(getattr(settings, "CLOUDFILE_RESOURCE_LIFECYCLE_READER", None))):
        raise ValueError("resource search requires OIDC, authorization and a native resource runtime")
    return validate_config(getattr(settings, "CLOUDFILE_RESOURCE_SEARCH_CONFIG", None))
