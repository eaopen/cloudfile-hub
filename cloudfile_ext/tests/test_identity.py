# -*- coding: utf-8 -*-
"""Identity resolution ordering.

This file exists because the first two attempts at resolve_user were wrong in
the same way, and nothing but a full stack caught it. The lookups are injected
here so the ordering is testable without Django, seaserv or a running server --
untestable logic is why the bug survived two rounds.

The failure being guarded against: an email that maps to a different identity
must never be stored verbatim. A rule stored against an email is compared
against nothing, so it never applies, and no error is raised anywhere -- the
folder just stays open while the administrator believes it is restricted.
"""

import pytest

from cloudfile_ext import identity


IDENTITY = '854d0a7e9998440c8c73854a59e8db9a@auth.local'
EMAIL = 'acl-matrix-b@example.com'


def mapping(table):
    """convert_login_str_to_username: returns its input when nothing maps."""
    return lambda s: table.get(s, s)


def accounts(*known):
    return lambda s: s in known


def test_email_resolves_to_identity():
    assert identity.resolve_user(
        EMAIL,
        map_email=mapping({EMAIL: IDENTITY}),
        account_exists=accounts(IDENTITY, EMAIL),
    ) == IDENTITY


def test_email_wins_even_though_it_names_an_account():
    """The regression that shipped twice.

    ccnet_api.get_emailuser resolves emails as well as identities, so an
    "is this already an identity?" check answers yes for an email. Ordering the
    existence check first therefore stores the email and the rule silently
    never matches. account_exists says yes to both here on purpose -- that is
    the real server's behaviour, and the resolution must still return the
    identity.
    """
    assert identity.resolve_user(
        EMAIL,
        map_email=mapping({EMAIL: IDENTITY}),
        account_exists=accounts(IDENTITY, EMAIL),   # both exist, as in reality
    ) == IDENTITY


def test_identity_passes_through():
    assert identity.resolve_user(
        IDENTITY,
        map_email=mapping({EMAIL: IDENTITY}),
        account_exists=accounts(IDENTITY),
    ) == IDENTITY


def test_pre_14_identity_equals_email():
    """Deployments where the two are the same string must keep working."""
    legacy = 'alice@example.com'
    assert identity.resolve_user(
        legacy,
        map_email=mapping({}),          # nothing to map
        account_exists=accounts(legacy),
    ) == legacy


def test_unknown_subject_is_refused():
    """A typo must not be stored. convert_login_str_to_username hands back its
    input when nothing maps, so without the existence check it would be."""
    with pytest.raises(identity.UnknownSubject):
        identity.resolve_user(
            'typo@example.com',
            map_email=mapping({EMAIL: IDENTITY}),
            account_exists=accounts(IDENTITY, EMAIL),
        )


def test_empty_subject_is_refused():
    with pytest.raises(identity.UnknownSubject):
        identity.resolve_user('   ', map_email=mapping({}),
                              account_exists=accounts())


def test_whitespace_is_stripped():
    assert identity.resolve_user(
        f'  {EMAIL} ',
        map_email=mapping({EMAIL: IDENTITY}),
        account_exists=accounts(IDENTITY),
    ) == IDENTITY


def test_ambiguous_mapping_is_refused_not_fallback():
    """Two identities on one contact_email must refuse, never guess.

    Falling through to account_exists here would resolve the email to
    *something* -- whichever account the server picks -- and the next full
    sync would move that person's group membership to it, leaving their other
    sessions able to log in but unable to see a single library. The mapping
    raising means the directory disagrees with itself about who this is.
    """

    def ambiguous(_):
        raise identity.AmbiguousSubject(EMAIL)

    with pytest.raises(identity.AmbiguousSubject):
        identity.resolve_user(
            EMAIL,
            map_email=ambiguous,
            account_exists=accounts(IDENTITY, EMAIL),  # fallback must not run
        )
