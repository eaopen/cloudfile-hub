# -*- coding: utf-8 -*-
"""Red tests for the three-state ACL authority contract.

These pin SEC-02 BEFORE any implementation exists (Wave 3 plans 01-03 / 01-04
deliver the Hub revision tracker and the Server authority-state RPC). The
fixture that drives them is the shared ``authority_states`` block in
cloudfile-docker/docs/acl-cases.json, the same file the C and Go suites read.

What is being locked here is the distinction the security boundary depends on:

    unsupported-stock  -> native CE pass-through (no RPC, no capability)
    inactive-disabled  -> native CE pass-through (capability off)
    active-valid       -> rule resolution against the current authority
    active-unavailable -> DENY at the content boundary (NOT pass-through)
    active-malformed   -> DENY
    active-stale       -> DENY on revision mismatch at the final boundary

The most dangerous bug this exists to prevent is conflating "active authority
unreachable" with "no restriction" -- the current Go fileserver
``cfFindRestrictedPath`` does exactly that, returning "" on any RPC error. A
green run of this module requires that conflation to be gone.

It is intentional that these tests FAIL today: the
``cloudfile_ext.acl.revision`` module is the Wave 3 deliverable. Each test
imports it defensively so the failure names the missing contract rather than
crashing on an unhandled ImportError.
"""

import json
import os

import pytest


def _cases_path():
    override = os.environ.get('CF_ACL_CASES')
    if override:
        return override
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.normpath(os.path.join(here, '..', '..', '..'))
    return os.path.join(os.path.dirname(repo_root),
                        'cloudfile-docker', 'docs', 'acl-cases.json')


def _authority_states():
    with open(_cases_path(), encoding='utf-8') as fp:
        data = json.load(fp)
    return data['authority_states']


def _import_revision_module():
    """Import the Wave 3 authority module, or fail naming what is missing.

    A bare ImportError would read as an environment problem; the explicit
    pytest.fail keeps the failure reason attached to the contract.
    """
    try:
        from cloudfile_ext.acl import revision
        return revision
    except ImportError as exc:
        pytest.fail(
            'cloudfile_ext.acl.revision is not implemented yet (Wave 3 plan '
            '01-03 delivers it). Authority-state contract cannot be '
            'verified until then. Underlying ImportError: %s' % exc)


# -- the three-state contract ------------------------------------------------


def test_states_table_is_loaded_and_has_the_six_canonical_states():
    """The fixture itself must keep the six canonical state names in lockstep
    with the spec. Adding or renaming a state without updating every consumer
    would silently re-open the security boundary."""
    states = {s['name']: s for s in _authority_states()['states']}
    expected = {
        'unsupported-stock', 'inactive-disabled', 'active-valid',
        'active-unavailable', 'active-malformed', 'active-stale',
    }
    assert set(states) == expected, (
        'authority_states fixture drifted from the six canonical names; '
        'missing=%s extra=%s' % (expected - set(states), set(states) - expected))


@pytest.mark.parametrize('state_name,expected_verdict', [
    ('unsupported-stock', 'passthrough'),
    ('inactive-disabled', 'passthrough'),
    ('active-valid', 'rules'),
    ('active-unavailable', 'deny'),
    ('active-malformed', 'deny'),
    ('active-stale', 'deny'),
])
def test_authority_verdict_per_state(state_name, expected_verdict):
    """The consumer must translate each authority state to the correct
    boundary verdict. The three 'active-*' outage states MUST be DENY; only
    the two genuinely-off states may pass through. This is the single test
    that fails if any consumer regresses to the 'empty string means no
    restriction' anti-pattern."""
    revision = _import_revision_module()
    state = next(s for s in _authority_states()['states']
                 if s['name'] == state_name)

    got = revision.classify(state)
    assert got == expected_verdict, (
        'state=%s expected verdict=%s got=%s -- an active authority outage '
        'classified as passthrough is the SEC-02 privilege escalation bug'
        % (state_name, expected_verdict, got))


def test_only_inactive_states_pass_through():
    """Negative guard: passthrough must be impossible once CF_ENABLE_DIR_ACL
    is on. If a future change adds a new active state and defaults it to
    passthrough, this fails immediately rather than after a security review."""
    revision = _import_revision_module()
    states = _authority_states()['states']
    for state in states:
        verdict = revision.classify(state)
        if state['feature_enabled']:
            assert verdict != 'passthrough', (
                'state %s has feature_enabled=true but classifies as '
                'passthrough -- an enabled authority must never silently '
                'delegate to the native CE path' % state['name'])


def test_unknown_authority_state_is_denied():
    """An unrecognized wire state is malformed authority data, never an
    invitation to fall back to native CE authorization."""
    revision = _import_revision_module()
    unknown = {
        'name': 'future-unknown-state',
        'feature_supported': True,
        'feature_enabled': True,
        'rpc_status': 'future-value',
        'issued_revision': 42,
        'current_revision': 42,
    }
    assert revision.classify(unknown) == \
        _authority_states()['unknown_state_verdict']


def test_revision_must_be_monotonic():
    """Revision monotonicity: every rule write (including clear-rules) must
    bump the counter, and a write may never produce a revision smaller than a
    prior one. Cache invalidation keys off this; a non-monotonic revision
    would let a cached 'deny' or 'allow' survive past a rule change."""
    revision = _import_revision_module()
    cases = _authority_states()['revision_monotonicity']

    # The harness starts from the lowest possible revision and replays the
    # fixture in order; a real implementation persists this counter in SQL.
    current = None
    for case in cases:
        nxt = revision.next_revision(current, case['op'])
        assert nxt == case['after'], (
            'op=%s before=%s expected revision=%s got=%s'
            % (case['op'], current, case['after'], nxt))
        if 'reject_rollback_to' in case:
            rolled = revision.next_revision(current, case['op'],
                                            force_target=case['reject_rollback_to'])
            assert rolled > case['reject_rollback_to'], (
                'revision rolled back to %s; monotonicity violated'
                % case['reject_rollback_to'])
        current = nxt


def test_final_boundary_rechecks_current_revision():
    """The revision observed at link/token issuance time must be rechecked at
    the content boundary. A cached verdict whose revision no longer matches
    the live authority must DENY, regardless of TTL remaining -- this is what
    makes 'revoke' immediate instead of waiting out the 300s fileserver
    cache."""
    revision = _import_revision_module()
    # Issued under revision 42, authority now reports 41.
    verdict = revision.recheck_at_boundary(
        issued_revision=42, current_revision=41,
        cached_restricted_path='/secret')
    assert verdict is None or getattr(verdict, 'denied', False), (
        'stale revision at the final boundary must DENY, not return the '
        'cached path; got=%r' % verdict)
