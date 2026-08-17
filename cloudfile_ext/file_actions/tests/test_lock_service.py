# -*- coding: utf-8 -*-
"""The Hub must preserve the C lease backend's fencing contract."""

import importlib
import sys
import types

import pytest


@pytest.fixture
def service(monkeypatch):
    """Import the adapter with only the Django names it reads at import time."""
    settings = types.SimpleNamespace(SITE_ROOT='/')
    conf = types.ModuleType('django.conf')
    conf.settings = settings
    cache = types.ModuleType('django.core.cache')
    cache.cache = types.SimpleNamespace()
    database = types.ModuleType('django.db')
    database.connections = {}
    django = types.ModuleType('django')
    django.conf = conf

    for name, module in (
            ('django', django), ('django.conf', conf),
            ('django.core', types.ModuleType('django.core')),
            ('django.core.cache', cache), ('django.db', database)):
        monkeypatch.setitem(sys.modules, name, module)
    monkeypatch.delitem(sys.modules, 'cloudfile_ext.file_actions.service',
                        raising=False)

    import cloudfile_ext.file_actions
    monkeypatch.delattr(cloudfile_ext.file_actions, 'service', raising=False)
    return importlib.import_module('cloudfile_ext.file_actions.service')


def test_refresh_sends_owner_and_generation_to_the_authority(service, monkeypatch):
    captured = {}

    def rpc(method, payload):
        captured['method'] = method
        captured['payload'] = payload
        return {'ok': True}

    monkeypatch.setattr(service, '_lock_rpc', rpc)
    assert service.refresh_lock('repo', '/plan.docx', 'owner', 'generation') == {'ok': True}
    assert captured == {
        'method': 'cf_lock_refresh',
        'payload': {
            'repo_id': 'repo', 'path': '/plan.docx', 'owner': 'owner',
            'generation': 'generation', 'lease_seconds': 12 * 60 * 60,
        },
    }


def test_force_release_is_fenced_to_the_generation_an_admin_reviewed(service, monkeypatch):
    captured = {}

    def rpc(method, payload):
        captured['method'] = method
        captured['payload'] = payload
        return {'ok': True}

    monkeypatch.setattr(service, '_lock_rpc', rpc)
    assert service.force_release_lock(
        'repo', '/plan.docx', 'admin', 'generation', 'recovery') == {'ok': True}
    assert captured == {
        'method': 'cf_lock_force_release',
        'payload': {
            'repo_id': 'repo', 'path': '/plan.docx', 'actor': 'admin',
            'generation': 'generation', 'reason': 'recovery',
        },
    }


def test_browser_descriptor_has_agent_protocol_mode_and_safe_filename(service):
    descriptor = service._agent_session_descriptor(
        'local-edit', '/plans/roadmap.docx', 'one-time-ticket', 60, 1000)

    assert descriptor == {
        'protocol': 'cloudfile-local/v2',
        'mode': 'local-edit',
        'file': {'name': 'roadmap.docx'},
        'ticket': 'one-time-ticket',
        'expires_in': 60,
        'expires_at': 1060,
    }
    assert 'content_url' not in repr(descriptor)
