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


def _default_map_email(subject):
    """Seahub's own login-string -> identity mapping. Returns input if unmapped."""
    from seahub.profile.models import Profile
    return Profile.objects.convert_login_str_to_username(subject)


def _default_account_exists(candidate):
    from seaserv import ccnet_api
    return bool(ccnet_api.get_emailuser(candidate))


def resolve_user(subject, map_email=None, account_exists=None):
    """Return the identity enforcement will see, for a typed user subject.

    Accepts the internal id or a login/contact email: an admin knows the email,
    while an API client may already hold the id.

    **The mapping is tried before the existence check, and that order is the
    whole point.** The obvious shape -- "if this already names an account, keep
    it; otherwise map it" -- looks right and is wrong, because
    ``ccnet_api.get_emailuser`` resolves an *email* too. An email therefore
    passes the "is this an identity?" test, gets kept verbatim, and the rule is
    stored against a string enforcement never compares. That is precisely the
    bug this module was written to fix, and the first version of it reproduced
    the bug exactly; the six-entry matrix caught it, unit tests did not.

    So: map first, and only fall back to the input when the mapping is a no-op.

    The mapping is Seahub's ``convert_login_str_to_username`` rather than a
    query of our own. It is what the rest of Seahub authenticates through, so
    borrowing it means a rule matches exactly the account that logging in
    produces; a private reimplementation would be one more thing to drift, and
    drift here means rules that quietly apply to nobody.

    The lookups are injectable so this ordering can be tested without Django,
    seaserv or a running server -- see tests/test_subjects.py.
    """
    map_email = map_email or _default_map_email
    account_exists = account_exists or _default_account_exists

    subject = (subject or '').strip()
    if not subject:
        raise UnknownSubject('empty subject')

    try:
        mapped = map_email(subject)
    except Exception as e:                                  # pragma: no cover
        logger.warning('login-string mapping for %s failed: %s', subject, e)
        mapped = None

    # A real mapping wins outright: this is the 14+ case where identity and
    # email differ.
    if mapped and mapped != subject:
        return mapped

    # No mapping. Either the input is already an identity, or it is a
    # pre-14 deployment where the two are the same string -- both fine, but
    # confirm the account exists rather than storing whatever was typed. Note
    # convert_login_str_to_username returns its input when nothing maps, so a
    # typo arrives here unchanged and must not slip through.
    try:
        if account_exists(subject):
            return subject
    except Exception as e:                                  # pragma: no cover
        logger.warning('account lookup for %s failed: %s', subject, e)

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
