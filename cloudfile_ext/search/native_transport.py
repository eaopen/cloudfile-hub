"""Explicit native transport selection; deployment skew never widens authority."""
from .access import unavailable
from .native_many import NativePermissionMany


def permission_transport(repo_id, username, api, hook, mode='batch'):
    if mode == 'batch':
        return None, NativePermissionMany(repo_id, username,
            api.cf_check_permissions_many, hook)
    if mode != 'scalar':
        raise unavailable()

    # Older production C servers expose the same path decision only as scalar
    # RPC. This operator-selected mode retains both exact-path passes and every
    # Hub narrowing hook; it never retries a failed batch through another path.
    def scalar(path):
        native = api.check_permission_by_path(repo_id, path, username)
        return hook(username, repo_id, path, native) if native in ('r', 'rw') else None

    return scalar, None
