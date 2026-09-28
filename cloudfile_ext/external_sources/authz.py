# -*- coding: utf-8 -*-
"""The authorisation vocabulary and decision, with no Django in sight.

Same split as the ACL capability's resolver.py: the rule that decides access is
a pure function over already-fetched facts, and the modules that talk to the
database import *from* here rather than the other way round. Two reasons, and
the second is the one that matters:

* The shared checks (cloudfile-docker/tools/run-checks.sh) install pytest and
  nothing else. A rule that needs Django to import is a rule whose tests are
  skipped in CI -- and a check that never runs reads as coverage while providing
  none.

* The ACL capability shipped a subject-resolution bug twice, and its own
  post-mortem (FEATURES.md item 71) names the cause: the logic was not reachable
  from a test without a running stack, so unit tests, static checks and the
  baseline gate were all green while the defect was untouched by any of them.

Everything here fails closed. There is no branch that grants access because no
deny condition matched: access comes from a grant existing, never from grants
being absent.
"""

import logging

logger = logging.getLogger(__name__)

#: The only permission an external source can grant in this release.
#:
#: Read-only is a product decision rather than a property of the data model, so
#: the column is general and the domain is enforced here. A narrow domain
#: enforced in code beats a wide one with a comment: a row carrying anything
#: else is ignored below rather than interpreted.
PERMISSION_R = 'r'
VALID_PERMISSIONS = (PERMISSION_R,)

SUBJECT_USER = 'user'
SUBJECT_GROUP = 'group'
VALID_SUBJECT_TYPES = (SUBJECT_USER, SUBJECT_GROUP)


def decide(grants, is_staff=False, group_ids=(), enabled=True):
    """The permission a user gets on one source, or None for no access.

    `grants` is an iterable of ``(subject_type, subject, permission)`` rows for
    that source, already narrowed to this user and their groups -- which is why
    a matching ``user`` row needs no further comparison here, and why this
    function never sees a username.

    `group_ids` are the user's ordinary group ids; they are compared as strings
    because that is how a group subject is stored (a group id is a number, but
    the column holds subjects of both kinds).

    `enabled` is the source's own flag. It is a parameter rather than something
    a caller filters on beforehand so that "disabled means nobody, including
    staff" is stated in the rule instead of relying on every query remembering
    to add the filter.
    """
    if not enabled:
        return None

    # Administrators can always read. They can already register, re-point and
    # delete a source, so withholding its contents would only mean granting it
    # to themselves before they can check that a new mount works.
    if is_staff:
        return PERMISSION_R

    wanted_groups = {str(gid) for gid in group_ids}

    for subject_type, subject, permission in grants:
        if permission not in VALID_PERMISSIONS:
            # Outside the domain: ignore the row rather than honour it. Acting
            # on it would grant whatever that string means to some later
            # version of this code, which is the one outcome nobody chose.
            logger.warning('external source grant has unknown permission %r; '
                           'ignoring', permission)
            continue
        if subject_type == SUBJECT_USER:
            return PERMISSION_R
        if subject_type == SUBJECT_GROUP:
            if str(subject) in wanted_groups:
                return PERMISSION_R
            continue
        logger.warning('external source grant has unknown subject_type %r; '
                       'ignoring', subject_type)

    return None
