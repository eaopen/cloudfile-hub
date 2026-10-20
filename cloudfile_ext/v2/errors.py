class IdentityUnavailable(RuntimeError):
    """No authenticated or fresh identity can be established."""


class IdentityConflict(IdentityUnavailable):
    """Stable native and external identities disagree."""


class SubjectNotFound(IdentityUnavailable):
    """The directory answered: this account has no business subject.

    Kept apart from IdentityUnavailable on purpose: "the directory says this
    account does not exist as a business subject" is a fact the caller can act
    on (skip the subject, fall back to native permission), while "the directory
    could not be reached" is an outage. Collapsing both into 503 makes an
    administrator-initiated call look like a network failure (DEV 2026-10-20).
    """
