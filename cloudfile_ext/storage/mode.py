"""Detect persisted V2 auto-local mode without introducing an S3 dependency."""
from configparser import ConfigParser
import os
from pathlib import Path


def auto_local_enabled(environ=None):
    env = os.environ if environ is None else environ
    if env.get("CF_LIBRARY_STORAGE") == "auto":
        return True

    # Existing auto-local deployments retain the persisted seafile.conf marker
    # even when CF_LIBRARY_STORAGE is subsequently omitted on restarts.
    candidates = []
    if env.get("SEAFILE_CENTRAL_CONF_DIR"):
        candidates.append(Path(env["SEAFILE_CENTRAL_CONF_DIR"]) / "seafile.conf")
    candidates.append(Path("/shared/seafile/conf/seafile.conf"))
    for filename in candidates:
        try:
            if filename.is_file():
                config = ConfigParser(interpolation=None)
                config.read(filename)
                return config.has_option("cloudfile_v2", "auto_local_root")
        except (OSError, ValueError):
            # A bad config must not grant a new allocation capability.
            return False
    return False
