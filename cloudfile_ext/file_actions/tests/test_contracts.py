# -*- coding: utf-8 -*-
"""Contract tests for the CloudFile file-action vocabulary.

Layer 1 (existing): disjoint read/write action sets and fencing.
Layer 2 (Wave 0, plan 01-09): the versioned local-session contract
(``cloudfile-local/v2``) that the Hub, the browser action, the Chrome
extension and the local agent share. These vocabulary assertions fail red
until the canonical constants, state enum and routes are exported from this
module (Wave 5 / plan 01-10 implements the authority; Wave 6 / plan 01-11
implements the browser and agent retry clients).
"""

import json
import os

import pytest

from cloudfile_ext.file_actions import contracts


def _load(path):
    with open(path, encoding='utf-8') as handle:
        return json.load(handle)


def _workspace_root():
    here = os.path.dirname(os.path.abspath(__file__))
    # cloudfile-hub/cloudfile_ext/file_actions/tests/test_contracts.py
    hub_root = os.path.abspath(os.path.join(here, '..', '..', '..'))
    return os.path.abspath(os.path.join(hub_root, '..'))


SCHEMA_PATH = os.path.join(_workspace_root(), 'cloudfile-docker', 'docs', 'local-session.schema.json')
CASES_PATH = os.path.join(_workspace_root(), 'cloudfile-docker', 'docs', 'local-session-cases.json')


def test_action_contract_has_disjoint_read_and_write_sets():
    assert contracts.READ_ACTIONS.isdisjoint(contracts.WRITE_ACTIONS)
    assert contracts.READ_ACTIONS | contracts.WRITE_ACTIONS == contracts.FILE_ACTIONS


def test_write_actions_require_server_fencing():
    assert contracts.writes_content(contracts.LOCAL_EDIT) is True
    assert contracts.writes_content(contracts.CHECKOUT) is True
    assert contracts.writes_content(contracts.LOCAL_VIEW) is False


def test_unknown_action_is_never_silently_treated_as_read_only():
    with pytest.raises(ValueError):
        contracts.writes_content('custom-write-action')


# --- Wave 0 (plan 01-09): versioned local-session vocabulary ---------------

def test_local_session_protocol_constant_is_the_canonical_v2():
    """The Hub, browser, extension and agent share one protocol identifier."""
    assert contracts.LOCAL_SESSION_PROTOCOL == 'cloudfile-local/v2'


def test_local_session_state_enum_is_fixed_and_ordered():
    """The status route emits exactly these state values, no fifth synonym."""
    assert contracts.LOCAL_SESSION_STATES == (
        'created', 'claimed', 'writing', 'saved', 'conflict', 'expired', 'failed',
    )


def test_local_session_modes_are_view_and_edit_only():
    assert set(contracts.LOCAL_SESSION_MODES) == {'local-view', 'local-edit'}


def test_local_session_detail_codes_never_carry_secrets():
    """detail_code is the only machine value the UI reads besides state; it
    must come from a fixed allowlist so a JWT, ticket, cookie or URL can never
    leak through it."""
    codes = set(contracts.LOCAL_SESSION_DETAIL_CODES)
    assert codes == {
        'claimed', 'writing', 'saved', 'saved_deduplicated',
        'conflict_generation', 'conflict_lock', 'expired', 'stale',
        'unsupported_protocol', 'origin_mismatch', 'ticket_reused', 'unavailable',
    }
    # Nothing that varies per-request may appear here.
    for forbidden in ('ticket', 'token', 'jwt', 'cookie', 'http', '/', ':'):
        for code in codes:
            assert forbidden not in code


def test_local_session_routes_are_the_canonical_paths():
    """Routes are pinned so the agent and extension tests assert the same URLs
    the Hub actually mounts."""
    assert contracts.LOCAL_SESSION_ROUTES == {
        'issue': '/api/v2.1/cloudfile/repos/{repo_id}/local-sessions/',
        'claim': '/api/v2.1/cloudfile/agent-sessions/claim/',
        'status': '/api/v2.1/cloudfile/local-sessions/{session_id}/status/',
        'heartbeat': '/api/v2.1/cloudfile/agent-sessions/{session_id}/heartbeat/',
        'writeback': '/api/v2.1/cloudfile/agent-sessions/{session_id}/content/',
    }


def test_local_session_contract_matches_golden_schema_and_cases():
    """The constants above must agree with the cross-client fixtures under
    cloudfile-docker/docs/. Drift here is exactly the bug LOCAL-01 exists to
    close: four clients inventing four subtly-different v2 shapes."""
    schema = _load(SCHEMA_PATH)
    cases = _load(CASES_PATH)
    assert schema['definitions']['protocol']['const'] == contracts.LOCAL_SESSION_PROTOCOL
    assert cases['protocol'] == contracts.LOCAL_SESSION_PROTOCOL
    assert tuple(cases['states']) == contracts.LOCAL_SESSION_STATES
    assert set(cases['modes']) == set(contracts.LOCAL_SESSION_MODES)
    assert cases['routes'] == contracts.LOCAL_SESSION_ROUTES
    # rejected_protocols must include the deprecated v1 so every consumer
    # fails closed on the abandoned helper shape.
    assert 'cloudfile-local/v1' in cases['rejected_protocols']
