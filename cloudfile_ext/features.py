# -*- coding: utf-8 -*-
"""CloudFile feature switches.

Every switch defaults to False. Turning them all off must restore native CE
behaviour, so nothing in cloudfile_ext may take effect without an explicit
opt-in here.

Switches are read from Django settings, which pick them up from
conf/seahub_settings.py, which the docker bootstrap writes from the compose
environment. Reading goes through this module rather than `settings.CF_*`
directly so that the switch list stays enumerable (the admin page and the
frontend context processor both iterate it).
"""

from django.conf import settings

#: Ordered so the admin UI and docs list the switches the same way.
FEATURES = (
    'CF_ENABLE_SSO',
    'CF_ENABLE_DIR_ACL',
    'CF_ENABLE_AUDIT',
    'CF_ENABLE_METADATA',
    'CF_ENABLE_TAGS',
    'CF_ENABLE_SEARCH',
    'CF_ENABLE_FILE_PREVIEW',
    'CF_ENABLE_ONLYOFFICE',
    'CF_ENABLE_FILE_LOCK',
    'CF_ENABLE_WATCH',
    'CF_ENABLE_CONVERT_EXPORT',
    'CF_ENABLE_CHECKOUT',
    'CF_ENABLE_LOCAL_APP',
    'CF_ENABLE_S3_STORAGE',
    'CF_ENABLE_EXTERNAL_SOURCES',
)


class UnknownFeature(Exception):
    """Raised for a feature name that is not in FEATURES.

    Deliberately fatal rather than falling back to False: a typo in a switch
    name would otherwise silently disable a feature the operator asked for.
    """


def is_enabled(name):
    """Return whether a CF_ENABLE_* switch is on."""
    if name not in FEATURES:
        raise UnknownFeature(name)
    return getattr(settings, name, False) is True


def enabled_features():
    """Return {switch_name: bool} for every known switch."""
    return {name: getattr(settings, name, False) is True for name in FEATURES}
