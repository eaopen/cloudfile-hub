# -*- coding: utf-8 -*-
"""ACL subjects, resolved the way every cf_* table resolves a user.

The resolution itself is in cloudfile_ext.identity -- it is a fact about
Seafile 14, not about ACL, and the SSO directory sync needs the same answer.
What stays here is the only ACL-specific part: which of the two resolvers a
subject_type calls for.
"""

from cloudfile_ext.identity import (            # noqa: F401  (re-exported)
    UnknownSubject, resolve_user, resolve_group,
)


def resolve(subject_type, subject):
    """Normalise `subject` for storage, or raise UnknownSubject."""
    from cloudfile_ext.acl import resolver

    if subject_type == resolver.SUBJECT_USER:
        return resolve_user(subject)
    return resolve_group(subject)
