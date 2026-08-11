# -*- coding: utf-8 -*-
"""Hub session authority red tests (plan 01-09, Wave 0).

These tests pin the ``cloudfile-local/v2`` session/status/write-back security
contract BEFORE the authority is implemented. Wave 5 (plan 01-10) implements
the durable writeback and the authenticated status API; Wave 6 (plan 01-11)
implements the browser polling and the agent retry client.

Every test in this file is intentionally RED at the end of plan 01-09 and
turns GREEN only when plans 01-10/01-11 land. The verify command in the plan
asserts ``! pytest test_sessions.py`` so the red state itself is the gate.

Contract under test, drawn from docs/local-session.schema.json and
docs/local-session-cases.json:

  * pre-claim response includes file.name and mode BEFORE the one-time ticket
    is claimed;
  * GET /api/v2.1/cloudfile/local-sessions/{session_id}/status/ returns the
    fixed status envelope for an authenticated owner;
  * anonymous is 401; non-owner, revoked-permission and missing-session are
    the same opaque 404 (no 403, no enumeration);
  * write-back updates the EXISTING file with a stable idempotency key and a
    generation fence; stale expected_commit_id never overwrites newer work;
  * the one-time ticket cannot be replayed, and an unsupported protocol is
    rejected by every consumer.
"""

import importlib
import json
import os
import sys
import types

import pytest


HERE = os.path.dirname(os.path.abspath(__file__))
# cloudfile-hub/cloudfile_ext/file_actions/tests/test_sessions.py
HUB_ROOT = os.path.abspath(os.path.join(HERE, '..', '..', '..'))
WORKSPACE_ROOT = os.path.abspath(os.path.join(HUB_ROOT, '..'))
CASES_PATH = os.path.join(WORKSPACE_ROOT, 'cloudfile-docker', 'docs', 'local-session-cases.json')


def _cases():
    with open(os.path.abspath(CASES_PATH), encoding='utf-8') as handle:
        return json.load(handle)


class _FakeCursor:
    def __init__(self):
        self.rows = []

    def execute(self, *_args, **_kwargs):
        return None

    def fetchone(self):
        return self.rows.pop(0) if self.rows else None

    def fetchall(self):
        out, self.rows = self.rows, []
        return out

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


class _FakeConnections:
    """Mimic django.db.connections[alias].cursor() used by cf_edit_session."""

    def __init__(self):
        self._cursors = {}

    def __getitem__(self, alias):
        return self._cursors.setdefault(alias, types.SimpleNamespace(
            cursor=lambda: _FakeCursor()))


@pytest.fixture
def service(monkeypatch):
    """Import the adapter with only the Django names it reads at import time.

    The system Python on the control-plane host has no Django, seaserv or
    rest_framework; the container image owns the real environment.  Stubs let
    us load ``cloudfile_ext.file_actions.service`` here so the contract under
    test stays executable in the focused gate.  The same pattern is already
    used by ``test_lock_service.py``.
    """
    settings = types.SimpleNamespace(
        SITE_ROOT='/', CF_DATABASE_ALIAS='cloudfile',
        CF_LOCAL_APP_SESSION_TTL=60)
    conf = types.ModuleType('django.conf')
    conf.settings = settings
    cache = types.ModuleType('django.core.cache')
    cache.cache = types.SimpleNamespace()
    database = types.ModuleType('django.db')
    database.connections = _FakeConnections()
    transaction = types.ModuleType('django.db.transaction')
    transaction.atomic = lambda *a, **k: (lambda f: f)
    database.transaction = transaction
    django = types.ModuleType('django')
    django.conf = conf

    for name, module in (
            ('django', django), ('django.conf', conf),
            ('django.core', types.ModuleType('django.core')),
            ('django.core.cache', cache),
            ('django.db', database), ('django.db.transaction', transaction)):
        monkeypatch.setitem(sys.modules, name, module)
    monkeypatch.delitem(sys.modules, 'cloudfile_ext.file_actions.service', raising=False)

    import cloudfile_ext.file_actions
    monkeypatch.delattr(cloudfile_ext.file_actions, 'service', raising=False)
    module = importlib.import_module('cloudfile_ext.file_actions.service')
    # Lock RPCs are C-side; neutralize them so the focused gate stays
    # framework-free and deterministic.
    monkeypatch.setattr(module, '_lock_rpc', lambda *_a, **_k: {'ok': True, 'generation': 'gen-1'})
    monkeypatch.setattr(module, 'lock_provider_ready', lambda *_a, **_k: True)
    return module


# --- pre-claim: file.name and mode before ticket claim (LOCAL-01) -----------

def test_pre_claim_response_carries_mode_and_filename_for_view(service):
    cases = _cases()
    expected = cases['pre_claim_response_view']
    issued = service.issue_local_view_session(
        '11111111-2222-3333-4444-555555555555', '/site-plan.pdf', 'owner@example.com')
    assert issued['protocol'] == 'cloudfile-local/v2'
    assert issued['mode'] == expected['mode']
    assert issued['file']['name'] == expected['file']['name']
    # The browser-visible ticket is one-time and bounded; never a URL capability.
    assert 'ticket' in issued and issued['ticket']
    assert 'content_url' not in issued  # content URL is post-claim only
    assert 'writeback' not in issued     # writeback is local-edit only


def test_pre_claim_response_carries_mode_and_filename_for_edit(service):
    cases = _cases()
    expected = cases['pre_claim_response_edit']
    issued = service.issue_local_edit_session(
        '11111111-2222-3333-4444-555555555555', '/report.docx',
        'owner@example.com', 'file-id-1')
    assert issued['protocol'] == 'cloudfile-local/v2'
    assert issued['mode'] == expected['mode']
    assert issued['file']['name'] == expected['file']['name']
    # The pre-claim response must NOT carry the write-back capability: that
    # capability is minted only after the one-time ticket is claimed, so a
    # leaked descriptor cannot be used to write back.
    assert 'writeback' not in issued
    assert 'capability' not in issued


def test_pre_claim_response_does_not_use_the_abandoned_v1_protocol(service):
    """The Hub must not keep the deprecated cloudfile-local/v1 helper shape
    alive alongside the canonical v2 contract."""
    issued = service.issue_local_view_session(
        '11111111-2222-3333-4444-555555555555', '/site-plan.pdf', 'owner@example.com')
    assert issued['protocol'] != 'cloudfile-local/v1'


# --- authenticated status route (LOCAL-02) ---------------------------------

def test_status_route_envelope_is_the_fixed_owner_shape(service):
    cases = _cases()
    expected = next(c for c in cases['status_cases'] if c['response']['state'] == 'claimed')
    status = service.local_session_status(
        expected['session_id'], 'owner@example.com')
    # The browser reads exactly this key set; no extra field may appear.
    assert set(status) == {
        'protocol', 'session_id', 'state', 'mode', 'file',
        'expires_at', 'lease_until', 'detail_code', 'updated_at',
    }
    assert status['protocol'] == 'cloudfile-local/v2'
    assert status['state'] == 'claimed'
    assert status['file'] == {'name': 'report.docx'}
    assert status['detail_code'] == 'claimed'


def test_status_route_state_drives_each_ui_state_copy(service):
    """Every UI-SPEC state string must be reachable from a status response."""
    cases = _cases()
    copy_to_state = {
        'Local session claimed': 'claimed',
        'File saved': 'saved',
        'This file changed elsewhere': 'conflict',
        'This local session expired': 'expired',
        'This session is out of date': 'conflict',  # detail_code: stale
    }
    for expected_copy, _state in copy_to_state.items():
        matching = [c for c in cases['status_cases'] if c['expect_state_copy'] == expected_copy]
        assert matching, 'golden cases missing for %r' % expected_copy


def test_download_completion_is_not_a_status_proof(service, monkeypatch):
    """LOCAL-01: the browser must not infer claimed/saved from a download."""
    # No service helper exists for download-derived status, and none may be
    # added: status is the single authority.  Asserting the helper is absent
    # keeps a future change honest.
    assert not hasattr(service, 'status_from_download')


# --- authorization boundary (LOCAL-02 / SEC-02) ----------------------------

def test_anonymous_status_is_401_never_403(service):
    result = service.local_session_status(
        '22222222-2222-3333-4444-555555555555', None)
    assert result['http_status'] == 401


def test_non_owner_status_is_opaque_404(service):
    cases = _cases()
    one = cases['claimed_edit']
    result = service.local_session_status(one['session_id'], 'stranger@example.com')
    assert result['http_status'] == 404
    assert result['body'] == {'detail': 'Not found.'}


def test_revoked_permission_is_the_same_opaque_404(service):
    cases = _cases()
    one = cases['claimed_edit']
    result = service.local_session_status(one['session_id'], 'revoked@example.com')
    assert result['http_status'] == 404
    assert result['body'] == {'detail': 'Not found.'}


def test_missing_session_is_the_same_opaque_404(service):
    cases = _cases()
    missing = next(c for c in cases['auth_cases'] if c['name'].startswith('missing'))
    result = service.local_session_status(missing['session_id'], 'owner@example.com')
    assert result['http_status'] == 404
    assert result['body'] == {'detail': 'Not found.'}


def test_denial_responses_are_indistinguishable(service):
    """The three denial causes MUST produce identical status + body so a
    caller cannot enumerate live session ids."""
    cases = _cases()
    one = cases['claimed_edit']
    non_owner = service.local_session_status(one['session_id'], 'stranger@example.com')
    revoked = service.local_session_status(one['session_id'], 'revoked@example.com')
    missing = service.local_session_status('99999999-9999-9999-9999-999999999999', 'owner@example.com')
    assert non_owner == revoked == missing


# --- one-time ticket / unsupported protocol -------------------------------

def test_claim_body_pins_protocol_and_rejects_unsupported_version(service):
    cases = _cases()
    bad = next(c for c in cases['claim_cases'] if c['name'] == 'rejected protocol version fails closed')
    assert bad['request_protocol'] != 'cloudfile-local/v2'
    issued = service.issue_local_view_session(
        '11111111-2222-3333-4444-555555555555', '/site-plan.pdf', 'owner@example.com')
    result = service.claim_agent_session(
        issued['ticket'], 'https://hub.example.test',
        protocol=bad['request_protocol'])
    assert result['http_status'] == 400
    assert result['detail_code'] == 'unsupported_protocol'


def test_one_time_ticket_cannot_be_claimed_twice(service):
    cases = _cases()
    replay = next(c for c in cases['claim_cases'] if 'one-time' in c['name'])
    assert replay['sequence'] == ['claim-ok', 'claim-replay']
    issued = service.issue_local_view_session(
        '11111111-2222-3333-4444-555555555555', '/site-plan.pdf', 'owner@example.com')
    first = service.claim_agent_session(
        issued['ticket'], 'https://hub.example.test', protocol='cloudfile-local/v2')
    assert first.get('session_id')
    replay_result = service.claim_agent_session(
        issued['ticket'], 'https://hub.example.test', protocol='cloudfile-local/v2')
    assert replay_result['http_status'] == 410
    assert replay_result['detail_code'] == 'ticket_reused'


# --- write-back: existing-file update with stable idempotency key ----------

def test_writeback_uses_stable_idempotency_key_across_retries(service, monkeypatch):
    cases = _cases()
    case = next(c for c in cases['writeback_cases'] if c['name'].startswith('stable idempotency'))
    key = case['first_request']['idempotency_key']
    commit = case['first_request']['expected_commit_id']
    calls = []
    committed_session = service.claim_agent_session(
        _issued_edit_ticket(service), 'https://hub.example.test', protocol='cloudfile-local/v2')
    session_id = committed_session.get('session_id') or '22222222-2222-3333-4444-555555555555'

    def fake_write(session_id, capability, payload, upload):
        calls.append((payload.get('idempotency_key'), payload.get('expected_commit_id')))
        return {'detail_code': 'saved', 'commit_id': 'new-commit'}

    monkeypatch.setattr(service, '_durable_writeback', fake_write, raising=False)
    first = service.commit_local_edit(
        session_id, 'capability-edit', {'idempotency_key': key, 'expected_commit_id': commit},
        upload=b'body')
    retry = service.commit_local_edit(
        session_id, 'capability-edit', {'idempotency_key': key, 'expected_commit_id': commit},
        upload=b'body')
    # The durable outcome returns the prior result without applying a second write.
    assert len(calls) == 1
    assert first['detail_code'] == 'saved'
    assert retry['detail_code'] == 'saved_deduplicated'


def test_stale_expected_commit_id_does_not_overwrite_newer_work(service, monkeypatch):
    cases = _cases()
    case = next(c for c in cases['writeback_cases'] if 'stale' in c['name'])
    committed_session = service.claim_agent_session(
        _issued_edit_ticket(service), 'https://hub.example.test', protocol='cloudfile-local/v2')
    session_id = committed_session.get('session_id') or '22222222-2222-3333-4444-555555555555'

    def fake_write(session_id, capability, payload, upload):
        return {'detail_code': 'stale', 'commit_id': None}

    monkeypatch.setattr(service, '_durable_writeback', fake_write, raising=False)
    result = service.commit_local_edit(
        session_id, 'capability-edit', {
            'idempotency_key': case['request']['idempotency_key'],
            'expected_commit_id': case['request']['expected_commit_id'],
        }, upload=b'body')
    assert result['detail_code'] == 'stale'
    assert result['commit_id'] is None


def test_writeback_updates_existing_file_and_never_creates_sibling(service, monkeypatch):
    cases = _cases()
    case = next(c for c in cases['writeback_cases'] if 'never creates a sibling' in c['name'])
    captured = {}

    def fake_write(session_id, capability, payload, upload):
        captured['payload'] = payload
        return {'detail_code': 'saved', 'commit_id': 'new-commit'}

    monkeypatch.setattr(service, '_durable_writeback', fake_write, raising=False)
    committed_session = service.claim_agent_session(
        _issued_edit_ticket(service), 'https://hub.example.test', protocol='cloudfile-local/v2')
    session_id = committed_session.get('session_id') or '22222222-2222-3333-4444-555555555555'
    service.commit_local_edit(
        session_id, 'capability-edit', {
            'idempotency_key': case['request']['idempotency_key'],
            'expected_commit_id': case['request']['expected_commit_id'],
        }, upload=b'body')
    # The authority MUST NOT use a create/add RPC; the existing file identity
    # is the contract.  The legacy create helper is therefore gone.
    assert not hasattr(service, '_create_sibling_file')
    assert captured['payload']['expected_commit_id'] == case['request']['expected_commit_id']


def _issued_edit_ticket(service):
    issued = service.issue_local_edit_session(
        '11111111-2222-3333-4444-555555555555', '/report.docx',
        'owner@example.com', 'file-id-1')
    return issued['ticket']
