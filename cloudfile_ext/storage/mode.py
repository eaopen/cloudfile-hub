"""Expose auto-local admin APIs only for the persisted Seafile configuration.

The startup environment expresses desired deployment state and can disagree with
the server's persisted routing. It must not independently enable the API.
"""
from configparser import ConfigParser, Error as ConfigError
import os
from pathlib import Path


def auto_local_enabled(environ=None):
    env = os.environ if environ is None else environ
    path = Path(env.get("SEAFILE_CENTRAL_CONF_DIR") or "/shared/seafile/conf") / "seafile.conf"
    try:
        config = ConfigParser(interpolation=None)
        if not path.is_file():
            return False
        config.read(path)
        return bool(config.get("cloudfile_v2", "auto_local_root", fallback="").strip())
    except (OSError, ConfigError, ValueError):
        # No runtime mode guess from CF_LIBRARY_STORAGE or a stale second config.
        return False
