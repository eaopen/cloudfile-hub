# -*- coding: utf-8 -*-
"""Resolve what a human or an external system names into what Seafile compares.

Seafile 14 decoupled a user's *identity* from their email. An account created
as ``alice@example.com`` gets an opaque id like
``0506008c6bcc462b8d4e85cf13443d7d@auth.local``; the email becomes a login
attribute. Everything below the Hub -- ``check_permission_by_path``, the
dirent filter, the subtree scan, group membership -- is handed that opaque id,
never the email.

So anything stored against the email is stored against a string that will
never match. Nothing errors, nothing logs; the folder simply stays open, or the
group simply stays empty. An administrator who restricted a folder and was told
it worked would be wrong, and would have no way to notice. That is the worst
shape a permission bug can take, so a subject is resolved when it is written
and an unresolvable one is refused.

Refusing rather than storing-and-hoping is the same judgement made for
provider names in cloudfile_ext.providers: a rule that silently does nothing is
worse than a request that visibly fails.

**Why this is baseline and not part of directory ACL**, where it was first
written: every capability that stores or compares a user name hits the same
Seafile-14 fact. Directory ACL stores rule subjects; SSO turns directory
members into group members. Leaving it in ``acl/`` would have made the SSO
sync import from the ACL capability at runtime, which by the coupling rules in
docs/BRANCHES.md would have merged two clusters that share nothing else --
and would have made ACL's switch decide whether SSO could resolve a user.
"""

import logging

logger = logging.getLogger(__name__)


class UnknownSubject(Exception):
    """No account/group answers to what the admin typed."""


class AmbiguousSubject(UnknownSubject):
    """More than one account answers to the same login string.

    Two Seafile identities carrying one contact_email means the directory can
    no longer say *who* a member is. Falling back to the existence check here
    would store membership against whichever account the API happens to
    return, and the other identity silently loses every group at the next
    sync -- the "only the last login sees the libraries" failure. Refuse
    instead, so the split shows up in the sync report (``unresolved``) rather
    than moving data between accounts.
    """


def _default_map_email(subject):
    """Seahub's own login-string -> identity mapping. Returns input if unmapped.

    ``MultipleObjectsReturned`` is re-raised as ``AmbiguousSubject`` rather
    than treated as "no mapping": a duplicated contact_email must refuse, not
    fall through to the existence check and land on an arbitrary account.
    """
    from django.core.exceptions import MultipleObjectsReturned
    from seahub.profile.models import Profile
    try:
        return Profile.objects.convert_login_str_to_username(subject)
    except MultipleObjectsReturned:
        raise AmbiguousSubject(subject)


def _default_account_exists(candidate):
    from seaserv import ccnet_api
    return bool(ccnet_api.get_emailuser(candidate))


def _default_group_exists(gid):
    from seaserv import ccnet_api
    return ccnet_api.get_group(gid) is not None


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
    except AmbiguousSubject:
        # An ambiguous mapping is never a "try the fallback" situation: the
        # directory disagrees with itself about who this is, and guessing an
        # account is how membership migrates between a person's identities.
        raise
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


def login_of(identity):
    """The login string the directory knows this identity by, or None.

    The reverse of ``resolve_user``: the per-user directory query is keyed by
    what the etech directory understands -- the employee number (工号), which
    the IdP sets as ``login_id`` -- and the login refresh receives the opaque
    identity from the session. Contact email is the fallback for profiles
    provisioned before login_id was populated. Returning None when the profile
    carries neither lets the caller skip the refresh rather than query
    ``/users/<identity>/groups`` and read "no such user" as a fact.
    """
    from seahub.profile.models import Profile

    profile = Profile.objects.get_profile_by_user(identity)
    if profile is None:
        return None
    login_id = (profile.login_id or '').strip()
    if login_id:
        return login_id
    return (profile.contact_email or '').strip() or None


#: Process-wide resolver for a directory dept's external id -> Seafile group
#: id. Installed by the SSO capability at startup when CF_ENABLE_SSO is on;
#: None means directory ACL resolves depts as native Seafile group ids (the
#: pre-SSO behaviour). Lives on the baseline so directory ACL reads it without
#: importing the SSO capability, and SSO sets it without importing directory
#: ACL -- neither capability depends on the other.
_DEFAULT_GROUP_MAP_RESOLVER = None


def set_default_group_map_resolver(resolver):
    """Install (or clear, with None) the external-id -> group-id resolver."""
    global _DEFAULT_GROUP_MAP_RESOLVER
    _DEFAULT_GROUP_MAP_RESOLVER = resolver


def default_group_map_resolver():
    """The installed resolver, or None."""
    return _DEFAULT_GROUP_MAP_RESOLVER


#: Process-wide resolver for the reverse direction: a Seafile group id -> the
#: directory's external id. Symmetric to _DEFAULT_GROUP_MAP_RESOLVER, so the
#: read path can translate a stored group subject back to the id the external
#: system (and its frontend) knows, e.g. ``583 -> '7'``. Installed by the SSO
#: capability at startup alongside the forward resolver; None means group ids
#: pass through unchanged (the pre-SSO behaviour).
_DEFAULT_GROUP_ID_RESOLVER = None


def set_default_group_id_resolver(resolver):
    """Install (or clear, with None) the group-id -> external-id resolver."""
    global _DEFAULT_GROUP_ID_RESOLVER
    _DEFAULT_GROUP_ID_RESOLVER = resolver


def default_group_id_resolver():
    """The installed reverse resolver, or None."""
    return _DEFAULT_GROUP_ID_RESOLVER


def resolve_group(subject, group_map=None, group_exists=None):
    """Return the Seafile group id enforcement compares, for a typed group.

    In an SSO deployment the directory's own id -- ``external_id`` -- differs
    from the Seafile group id that group membership is enforced against
    (``cf_sso_group_map``). ``external_id`` is a string: a bare numeric
    department id, a snowflake id, or a ``role:<id>``. When a mapping is
    available it is consulted first and, when it answers, its answer wins
    outright.

    The translation is deliberately *fall-back*, not fail-closed: a subject
    that is not a known external id is re-read as a native Seafile group id.
    Both shapes exist in the wild -- departments were written by external id,
    roles by Seafile group id -- and refusing the latter would break live
    rules. The order still keeps the dangerous case correct: on a numeric
    collision (``7`` is external id of one dept and Seafile group id of a
    different group) the external id wins, so a client meaning the dept is
    never silently pointed at the group.

    ``group_map`` is injectable for the same reason ``resolve_user`` takes
    ``map_email``: identity is baseline, and must not depend on the SSO
    capability that owns ``cf_sso_group_map``. When omitted, the process-wide
    default installed by the SSO capability is used, so callers that only
    import ``identity`` still get the translation when SSO is on.

    :param subject: an external id (when mapped) or a numeric Seafile group
        id, as typed by an admin or API client
    :param group_map: callable ``external_id -> seafile_group_id | None``,
        None to use the installed default, or a false value to skip mapping
    :param group_exists: callable ``gid -> bool``, injectable for tests
    """
    group_exists = group_exists or _default_group_exists

    subject = str(subject).strip()

    if group_map is None:
        group_map = default_group_map_resolver()

    if group_map:
        try:
            mapped = group_map(subject)
        except Exception as e:                              # pragma: no cover
            logger.warning('group-map lookup for %s failed: %s', subject, e)
            mapped = None
        if mapped is not None:
            return str(mapped)
        # Not a known external id: fall through to the native group-id check
        # below, so a raw Seafile group id keeps working (the pre-SSO shape).

    try:
        gid = int(subject)
    except (TypeError, ValueError):
        raise UnknownSubject('group subject must be a numeric id: %r' % (subject,))

    try:
        if not group_exists(gid):
            raise UnknownSubject('no such group: %s' % gid)
    except UnknownSubject:
        raise
    except Exception as e:                                  # pragma: no cover
        logger.warning('get_group(%s) failed: %s', gid, e)

    return str(gid)
