# -*- coding: utf-8 -*-
"""Selecting a directory source, and what each source does with a bad answer.

The invariant worth protecting is the same one the reconciler's guards protect,
one layer earlier: **a failed call must never arrive at the reconciler looking
like an empty directory.** Every path below that could return "no groups"
without having spoken to a directory is turned into DirectoryError here, so the
reconciler only ever sees snapshots that were actually read.

Django-free, like the rest of cloudfile_ext's tests: the shared checks install
pytest and nothing else.
"""

import importlib
import sys
import types

import pytest


@pytest.fixture
def cf(monkeypatch):
    """Import the provider machinery against a stub settings object."""
    conf = types.ModuleType('django.conf')
    conf.settings = types.SimpleNamespace()
    django = types.ModuleType('django')
    django.conf = conf
    monkeypatch.setitem(sys.modules, 'django', django)
    monkeypatch.setitem(sys.modules, 'django.conf', conf)

    for name in ('cloudfile_ext.providers', 'cloudfile_ext.registry',
                 'cloudfile_ext.sso.directory'):
        monkeypatch.delitem(sys.modules, name, raising=False)
    import cloudfile_ext
    import cloudfile_ext.sso
    for attr in ('providers', 'registry'):
        monkeypatch.delattr(cloudfile_ext, attr, raising=False)
    monkeypatch.delattr(cloudfile_ext.sso, 'directory', raising=False)

    registry_mod = importlib.import_module('cloudfile_ext.registry')
    directory = importlib.import_module('cloudfile_ext.sso.directory')
    reg = registry_mod.Registry()
    directory.register(reg)
    return types.SimpleNamespace(directory=directory, registry=reg,
                                 settings=conf.settings)


# -- selection -------------------------------------------------------------

def test_no_selection_means_no_mapping(cf):
    """CF_ENABLE_SSO with no directory is a real deployment, not a mistake.

    It is "use upstream's OAuth login, do not touch my groups". Inventing a
    default here would start rewriting group membership in a deployment whose
    operator only asked for single sign-on.
    """
    assert cf.directory.active(cf.registry) is None


def test_selecting_a_source_that_is_not_built_fails_loudly(cf):
    from cloudfile_ext.providers import UnknownProvider

    cf.settings.CF_PROVIDER_SSO_DIRECTORY = 'ldap'
    with pytest.raises(UnknownProvider):
        cf.directory.active(cf.registry)


def test_both_sources_are_registered(cf):
    cf.settings.CF_PROVIDER_SSO_DIRECTORY = cf.directory.STATIC
    assert isinstance(cf.directory.active(cf.registry),
                      cf.directory.StaticDirectory)

    cf.settings.CF_PROVIDER_SSO_DIRECTORY = cf.directory.EXTERNAL_SERVICE
    assert isinstance(cf.directory.active(cf.registry),
                      cf.directory.ExternalServiceDirectory)


# -- the static source -----------------------------------------------------

def test_static_source_reads_the_configured_groups(cf):
    cf.settings.CF_SSO_DIRECTORY_STATIC = [
        {'external_id': 'eng', 'name': 'Engineering', 'members': ['a']},
    ]
    source = cf.directory.StaticDirectory()
    assert source.groups() == [
        {'external_id': 'eng', 'name': 'Engineering', 'members': ['a']}]


def test_static_source_rejects_a_malformed_setting(cf):
    """A dict here is the obvious typo, and it iterates -- as its keys.

    Left unchecked it reaches the reconciler as a list of strings, every one of
    them a group without an external_id.
    """
    cf.settings.CF_SSO_DIRECTORY_STATIC = {'eng': ['a']}
    with pytest.raises(cf.directory.DirectoryError):
        cf.directory.StaticDirectory().groups()


def test_static_source_answers_per_user_case_insensitively(cf):
    cf.settings.CF_SSO_DIRECTORY_STATIC = [
        {'external_id': 'eng', 'members': ['Alice@Example.com']},
        {'external_id': 'sales', 'members': ['bob@example.com']},
    ]
    source = cf.directory.StaticDirectory()
    assert source.groups_for_user('alice@example.com') == ['eng']
    assert source.groups_for_user('nobody@example.com') == []


# -- the external service source -------------------------------------------

class FakeService(object):
    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def call(self, path, payload=None, method='POST'):
        self.calls.append((method, path))
        answer = self.answers[path]
        if isinstance(answer, Exception):
            raise answer
        return answer


def test_external_source_returns_what_the_service_says(cf):
    service = FakeService({'/groups': {'groups': [
        {'external_id': 'eng', 'name': 'Engineering', 'members': ['a']}]}})
    source = cf.directory.ExternalServiceDirectory(service=service)

    # The whole payload is returned, not just the list: a hierarchical feed
    # wraps it with 'revision', which build_plan reads.
    assert source.groups()['groups'][0]['external_id'] == 'eng'
    assert service.calls == [('GET', '/groups')]


def test_a_fail_open_service_does_not_become_an_empty_directory(cf):
    """ExternalService returns None when it is configured to fail open.

    Passing that through as "no groups" would hand the reconciler a snapshot
    nobody produced. Its own empty-snapshot guard would catch the common case,
    but only while something is already mapped -- on a first run it would
    happily conclude the directory is empty.
    """
    service = FakeService({'/groups': None})
    with pytest.raises(cf.directory.DirectoryError):
        cf.directory.ExternalServiceDirectory(service=service).groups()


def test_a_response_without_groups_is_an_error_not_an_empty_directory(cf):
    service = FakeService({'/groups': {'detail': 'not found'}})
    with pytest.raises(cf.directory.DirectoryError):
        cf.directory.ExternalServiceDirectory(service=service).groups()


def test_a_failed_call_is_an_error(cf):
    from cloudfile_ext.external_service import ExternalServiceError

    service = FakeService({'/groups': ExternalServiceError('boom')})
    with pytest.raises(cf.directory.DirectoryError):
        cf.directory.ExternalServiceDirectory(service=service).groups()


def test_a_missing_per_user_endpoint_is_not_an_error(cf):
    """It is optional; a service without it just means waiting for the tick."""
    from cloudfile_ext.external_service import ExternalServiceError

    service = FakeService({'/users/a/groups': ExternalServiceError('404')})
    source = cf.directory.ExternalServiceDirectory(service=service)
    assert source.groups_for_user('a') is None


def test_selecting_external_service_without_a_url_says_so(cf):
    """The configuration mistake that otherwise surfaces as an empty sync."""
    with pytest.raises(cf.directory.DirectoryError) as exc:
        cf.directory.ExternalServiceDirectory().groups()
    assert 'CF_SERVICE_SSO_DIRECTORY_URL' in str(exc.value)
