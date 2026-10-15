"""Live native system-administrator qualification, without loading User."""


def system_admin_content_role(role, permissions):
    # Background library management alone must not expose every file.
    return role == 'system_admin' and permissions.get('can_manage_library') is True


def is_system_library_admin(username):
    from seaserv import ccnet_api
    account = ccnet_api.get_emailuser(username)
    if (account is None or account.email != username
            or account.is_active != 1 or account.is_staff != 1):
        return False
    from seahub.role_permissions.models import AdminRole
    from seahub.role_permissions.utils import get_enabled_admin_role_permissions_by_role
    try:
        role = AdminRole.objects.get_admin_role(username).role
    except AdminRole.DoesNotExist:
        role = 'system_admin'  # Preserve CE's default only for an absent role row.
    if role != 'system_admin':
        return False
    return system_admin_content_role(role, get_enabled_admin_role_permissions_by_role(role))
