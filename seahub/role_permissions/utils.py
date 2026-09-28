# Copyright (c) 2012-2016 Seafile Ltd.
import logging

from .settings import ENABLED_ROLE_PERMISSIONS, ENABLED_ADMIN_ROLE_PERMISSIONS

from django.conf import settings

from seahub.constants import DEFAULT_USER, SYSTEM_ADMIN

logger = logging.getLogger(__name__)


def role_permissions_enabled():
    """Enable role management in CloudFile without exposing unrelated Pro endpoints."""
    from seahub.utils import is_pro_version
    return getattr(settings, 'CLOUDFILE_ROLE_PERMISSIONS_ENABLED', False) is True or is_pro_version()


def get_available_roles():
    """Get available roles defined in `ENABLED_ROLE_PERMISSIONS`.
    """
    return list(ENABLED_ROLE_PERMISSIONS.keys())


def get_enabled_role_permissions_by_role(role=DEFAULT_USER):
    """Get permissions dict(perm_name: bool) of a role.
    """
    if not role:
        role = DEFAULT_USER
    
    if role not in list(ENABLED_ROLE_PERMISSIONS.keys()):
        logger.warning('%s is not a valid role, use default role.' % role)
        role = DEFAULT_USER

    return ENABLED_ROLE_PERMISSIONS[role]


def get_available_admin_roles():
    """Get available admin roles defined in `ENABLED_ADMIN_ROLE_PERMISSIONS`.
    """
    return list(ENABLED_ADMIN_ROLE_PERMISSIONS.keys())


def get_enabled_admin_role_permissions_by_role(role):
    """Get permissions dict(perm_name: bool) of a admin role.
    """

    if not role:
        role = SYSTEM_ADMIN

    if role not in list(ENABLED_ADMIN_ROLE_PERMISSIONS.keys()):
        logger.warning('%s is not a valid admin role; deny its permissions.' % role)
        return {permission: False for permission in ENABLED_ADMIN_ROLE_PERMISSIONS[SYSTEM_ADMIN]}

    return ENABLED_ADMIN_ROLE_PERMISSIONS[role]
