"""Validate the same private export configuration in HTTP and worker hosts."""
import os
import stat


def require_export_configuration(settings):
    for name in ("CLOUDFILE_AUDIT_EXPORT_ENABLED", "CLOUDFILE_AUDIT_QUERY_ENABLED",
                 "CLOUDFILE_OIDC_ENABLED", "CLOUDFILE_AUTHORIZATION_ENABLED"):
        if getattr(settings, name, False) is not True:
            raise ValueError("audit export requires explicit audit, OIDC and authorization enablement")
    root = getattr(settings, "CLOUDFILE_AUDIT_RESULT_ROOT", None)
    if not isinstance(root, str) or not os.path.isabs(root):
        raise ValueError("audit export requires a private absolute result directory")
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        details = os.fstat(descriptor)
        if (not stat.S_ISDIR(details.st_mode) or details.st_uid != os.geteuid()
                or stat.S_IMODE(details.st_mode) != 0o700):
            raise ValueError("audit export directory must be owned by the service with mode 0700")
    finally:
        os.close(descriptor)
    return root
