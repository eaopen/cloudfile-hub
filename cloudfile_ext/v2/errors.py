class IdentityUnavailable(RuntimeError):
    """No authenticated or fresh identity can be established."""


class SubjectNotBound(IdentityUnavailable):
    """The native account carries no trusted stable UID to authorize."""


class IdentityConflict(IdentityUnavailable):
    """Stable native and external identities disagree."""
