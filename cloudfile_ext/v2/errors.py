class IdentityUnavailable(RuntimeError):
    """No authenticated or fresh identity can be established."""


class IdentityConflict(IdentityUnavailable):
    """Stable native and external identities disagree."""
