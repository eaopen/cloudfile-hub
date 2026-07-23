# -*- coding: utf-8 -*-
"""Resolve what an admin types into what enforcement actually compares.

Seafile 14 decoupled a user's *identity* from their email. An account created
as ``alice@example.com`` gets an opaque id like
``0506008c6bcc462b8d4e85cf13443d7d@auth.local``; the email becomes a login
attribute. Everything below the Hub -- ``check_permission_by_path``, the
dirent filter, the subtree scan -- is handed that opaque id, never the email.

So a rule stored against the email is a rule that can never match. Nothing
errors, nothing logs; the folder simply stays open. An administrator who
restricted a folder and was told it worked would be wrong, and would have no
way to notice. That is the worst shape a permission bug can take, so the
subject is resolved at write time and an unresolvable one is refused.

Refusing rather than storing-and-hoping is the same judgement made for
provider names in cloudfile_ext.providers: a rule that silently does nothing is
worse than a request that visibly fails.
"""

import logging

logger = logging.getLogger(__name__)


class UnknownSubject(Exception):
    """No account/group answers to what the admin typed."""


def resolve_user(subject):
    """Return the identity enforcement will see, for a typed user subject.

    Accepts either the internal id or a login email, because an admin knows
    the email and an API client may already hold the id.
    """
    from seaserv import ccnet_api

    subject = (subject or '').strip()
    if not subject:
        raise UnknownSubject('empty subject')

    # Already an identity?
    try:
        if ccnet_api.get_emailuser(subject):
            return subject
    except Exception as e:                                  # pragma: no cover
        logger.warning('get_emailuser(%s) failed: %s', subject, e)

    # Otherwise treat it as a login email and look the account up. Profile
    # holds the mapping in 14; older deployments have identity == email and
    # will have matched above.
    try:
        from seahub.profile.models import Profile
        profile = Profile.objects.filter(login_id=subject).first() \
            or Profile.objects.filter(contact_email=subject).first()
        if profile and profile.user:
            return profile.user
    except Exception as e:                                  # pragma: no cover
        logger.warning('profile lookup for %s failed: %s', subject, e)

    try:
        user = ccnet_api.get_emailuser_by_email(subject)
        if user:
            return user.email
    except Exception:
        pass

    raise UnknownSubject(subject)


def resolve_group(subject):
    """Group and department subjects are numeric ids; validate rather than map."""
    from seaserv import ccnet_api

    try:
        gid = int(str(subject).strip())
    except (TypeError, ValueError):
        raise UnknownSubject('group subject must be a numeric id: %r' % (subject,))

    try:
        if ccnet_api.get_group(gid) is None:
            raise UnknownSubject('no such group: %s' % gid)
    except UnknownSubject:
        raise
    except Exception as e:                                  # pragma: no cover
        logger.warning('get_group(%s) failed: %s', gid, e)

    return str(gid)


def resolve(subject_type, subject):
    """Normalise `subject` for storage, or raise UnknownSubject."""
    from cloudfile_ext.acl import resolver

    if subject_type == resolver.SUBJECT_USER:
        return resolve_user(subject)
    return resolve_group(subject)
