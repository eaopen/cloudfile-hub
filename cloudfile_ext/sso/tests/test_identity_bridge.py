"""Stable EAP logins are resolved via indexed CE Profile.login_id, never email."""
import pytest
from cloudfile_ext.sso.identity_bridge import load_login_identities, IdentityBridgeError
from cloudfile_ext.sso import snapshot


def test_bulk_identity_queries_are_bounded_and_deduplicated():
    calls = []
    def fetch(batch):
        calls.append(list(batch))
        return [(login, 'opaque:' + login) for login in batch]
    result = load_login_identities(['2', '1', '2', '3'], fetch=fetch, batch_size=2)
    assert result == {'1': 'opaque:1', '2': 'opaque:2', '3': 'opaque:3'}
    assert calls == [['1', '2'], ['3']]


def test_missing_profile_is_not_implicitly_created_or_guessed():
    assert load_login_identities(['employee-1'], fetch=lambda batch: []) == {}


def test_wrong_profile_login_is_not_accepted():
    with pytest.raises(IdentityBridgeError):
        load_login_identities(['employee-1'], fetch=lambda batch: [('wrong', 'opaque')])


def test_conflicting_bindings_are_isolated_without_blocking_healthy_profiles():
    assert load_login_identities(['employee-1', 'employee-2'], fetch=lambda batch: [
        ('employee-1', 'a'), ('employee-1', 'b'), ('employee-2', 'healthy')]) == {'employee-2': 'healthy'}


def test_member_login_ids_survive_snapshot_normalization():
    entries = snapshot.validate([{
        'external_id': 'dept-1', 'name': 'Dev', 'subject_type': 'dept',
        'member_user_ids': ['user-1'], 'member_login_ids': ['employee-001'],
        'member_accounts': ['alias@example.com']}])
    assert entries[0]['member_login_ids'] == ['employee-001']
    assert entries[0]['members'] == ['user-1']


def test_old_snapshots_do_not_gain_login_ids():
    entries = snapshot.validate([{
        'external_id': 'dept-1', 'name': 'Dev', 'members': ['alice@example.com']}])
    assert 'member_login_ids' not in entries[0]


def test_malformed_login_id_list_fails_closed():
    with pytest.raises(snapshot.SnapshotRejected, match='member_login_ids'):
        snapshot.validate([{
            'external_id': 'dept-1', 'name': 'Dev', 'member_user_ids': ['u1'],
            'member_login_ids': 'employee-1'}])


@pytest.fixture
def directory_service(monkeypatch):
    import importlib
    import sys
    import types
    models = types.ModuleType('cloudfile_ext.sso.models')
    models.SSOGroupMap = object
    models.SSOSyncState = object
    monkeypatch.setitem(sys.modules, 'cloudfile_ext.sso.models', models)
    monkeypatch.delitem(sys.modules, 'cloudfile_ext.sso.service', raising=False)
    return importlib.import_module('cloudfile_ext.sso.service')


def test_v2_member_resolution_uses_login_not_email(monkeypatch, directory_service):
    monkeypatch.setattr(directory_service, 'load_login_identities',
                        lambda logins: {'employee-001': 'native-42'})
    entries = snapshot.validate([{
        'external_id': 'dept-27', 'name': 'Dept 27', 'subject_type': 'dept',
        'member_user_ids': ['u42'], 'member_login_ids': ['employee-001'],
        'member_accounts': ['wrong-legacy-email@example.com']}])
    resolved, missing, quarantined = directory_service._resolve_members(entries)
    assert resolved[0]['members'] == ['native-42']
    assert missing == []
    assert quarantined == set()


def test_v2_missing_login_mapping_quarantines_group(monkeypatch, directory_service):
    monkeypatch.setattr(directory_service, 'load_login_identities',
                        lambda logins: {'a': 'native-a'})
    entries = snapshot.validate([{
        'external_id': 'dept-27', 'name': 'Dept 27', 'subject_type': 'dept',
        'member_user_ids': ['u1', 'u2'],
        'member_login_ids': ['a']}])
    resolved, missing, quarantined = directory_service._resolve_members(entries)
    assert resolved[0]['members'] == ['native-a']
    assert 'dept-27' in quarantined
    assert any('incomplete' in msg for msg in missing)


def test_v2_unprovisioned_identity_never_falls_back_to_email(monkeypatch, directory_service):
    monkeypatch.setattr(directory_service, 'load_login_identities', lambda logins: {})
    entries = snapshot.validate([{
        'external_id': 'dept-27', 'name': 'Dept 27', 'subject_type': 'dept',
        'member_user_ids': ['u42'], 'member_login_ids': ['employee-001'],
        'member_accounts': ['some-existing-other-user@example.com']}])
    resolved, missing, quarantined = directory_service._resolve_members(entries)
    assert resolved[0]['members'] == []
    assert 'employee-001' in missing
    assert quarantined == {'dept-27'}


# Canonical v2.2: exact EAP uid + employee number in one row, never positional.
from cloudfile_ext.sso.identity_bridge import resolve_eap_pairs


def test_eap_uid_binding_never_uses_employee_only_profile():
    db = {'uid-1': 'native-1', 'emp-1': 'native-1', 'emp-2': 'native-2'}
    resolved = resolve_eap_pairs([
        {'user_id': 'uid-1', 'employee_no': 'emp-1'},
        {'user_id': 'uid-2', 'employee_no': 'emp-2'},
        {'user_id': 'uid-3', 'employee_no': None}],
        fetch=lambda keys: [(key, db[key]) for key in keys if key in db])
    # Recycled employee numbers cannot inherit another native account's files.
    assert resolved == {'uid-1': 'native-1'}


def test_employee_profile_does_not_override_exact_uid_binding():
    db = {'uid-1': 'native-1', 'emp-1': 'someone-else'}
    assert resolve_eap_pairs([{'user_id': 'uid-1', 'employee_no': 'emp-1'}],
                            fetch=lambda keys: [(key, db[key]) for key in keys if key in db]) == {'uid-1': 'native-1'}


@pytest.mark.parametrize('employee,native', [
    ('cfadmin', 'native-admin'), ('CFADMIN', 'native-admin'),
    ('emp-1', 'cfadmin@etech.com'), ('emp-1', 'cfadmin@auth.local')])
def test_system_admin_is_excluded_from_employee_projection(employee, native):
    # System administration remains independent even if a bad feed includes it.
    assert resolve_eap_pairs([{'user_id': 'uid-1', 'employee_no': employee}],
                             fetch=lambda keys: [('uid-1', native)]) == {}


def test_employee_reused_for_different_uid_never_merges_native_accounts():
    mapped = resolve_eap_pairs([
        {'user_id': 'uid-1', 'employee_no': 'emp'},
        {'user_id': 'uid-2', 'employee_no': 'emp'}],
        fetch=lambda keys: [(key, 'native-legacy') for key in keys if key == 'emp'])
    assert mapped == {}  # employee-only fallback is ambiguous


def test_duplicate_employee_keeps_uid_first_identity():
    db = {'uid-1': 'native-uid-1', 'emp': 'native-legacy'}
    mapped = resolve_eap_pairs([
        {'user_id': 'uid-1', 'employee_no': 'emp'},
        {'user_id': 'uid-2', 'employee_no': 'emp'}],
        fetch=lambda keys: [(key, db[key]) for key in keys if key in db])
    assert mapped == {'uid-1': 'native-uid-1'}


def test_duplicate_employee_isolates_only_affected_groups():
    rows = snapshot.validate([
        {'external_id': 'dept-A', 'name': 'A',
         'member_user_ids': ['uid-1'],
         'member_identities': [{'user_id': 'uid-1', 'employee_no': 'emp'}]},
        {'external_id': 'dept-B', 'name': 'B',
         'member_user_ids': ['uid-2'],
         'member_identities': [{'user_id': 'uid-2', 'employee_no': 'emp'}]},
        {'external_id': 'dept-C', 'name': 'C',
         'member_user_ids': ['uid-3'],
         'member_identities': [{'user_id': 'uid-3', 'employee_no': 'unique'}]}])
    assert [x.get('identity_conflict', False) for x in rows] == [True, True, False]


def test_eap_pairs_cannot_shift_when_one_employee_number_missing():
    normalized = snapshot.validate([{
        'external_id': 'dept-1', 'name': 'Development',
        'member_user_ids': ['u1', 'u2'],
        'member_login_ids': ['employee-2'],
        'member_identities': [
            {'user_id': 'u2', 'employee_no': 'employee-2'},
            {'user_id': 'u1', 'employee_no': None}],
    }])
    assert normalized[0]['member_identities'] == [
        {'user_id': 'u1', 'employee_no': None},
        {'user_id': 'u2', 'employee_no': 'employee-2'}]


def test_eap_uid_member_incomplete_list_fails_before_reconciliation():
    with pytest.raises(snapshot.SnapshotRejected, match='do not match'):
        snapshot.validate([{'external_id': 'dept-1', 'name': 'Development',
            'member_user_ids': ['u1','u2'],
            'member_identities': [{'user_id': 'u1','employee_no': 'emp-1'}]}])


def test_eap_uid_mapping_takes_priority_in_real_resolver(monkeypatch, directory_service):
    monkeypatch.setattr(directory_service, 'resolve_eap_pairs', lambda pairs: {'u1': 'native-u1'})
    entries = snapshot.validate([{
        'external_id': 'dept-1', 'name': 'Development',
        'member_user_ids': ['u1','u2'],
        'member_login_ids': ['emp-1','emp-2'],
        'member_identities': [{'user_id': 'u1', 'employee_no': 'emp-1'},
                              {'user_id': 'u2', 'employee_no': 'emp-2'}]}])
    rows, unresolved, quarantined = directory_service._resolve_members(entries)
    assert rows[0]['members'] == ['native-u1']
    assert 'u2' in unresolved
    assert quarantined == {'dept-1'}


def test_eap_hutool_explicit_empty_employee_number_is_quarantinable():
    normalized = snapshot.validate([{
        'external_id': 'dept', 'name': 'Dept',
        'member_user_ids': ['uid-1'],
        'member_identities': [{'user_id': 'uid-1', 'employee_no': ''}]}])
    assert normalized[0]['member_identities'] == [
        {'user_id': 'uid-1', 'employee_no': None}]


@pytest.mark.parametrize('result,expected', [
    ({'status': 'ok', 'applied': {'add': 2, 'remove': 1}}, 3),
    ({'status': 'refused'}, None), ({'status': 'error'}, None)])
def test_login_refresh_uses_uid_context_and_keeps_refusals_retryable(monkeypatch, directory_service, result, expected):
    import sys
    import types
    from unittest.mock import Mock
    # A refused v2 delta must never downgrade to the legacy additions-only query.
    source = types.SimpleNamespace(context_for_user_id=Mock(), groups_for_user=Mock())
    monkeypatch.setitem(sys.modules, 'seaserv', types.SimpleNamespace(ccnet_api=object()))
    import cloudfile_ext.identity as identity
    monkeypatch.setattr(identity, 'login_of', lambda native: 'uid-42')
    monkeypatch.setattr(directory_service.directory, 'active', lambda registry: source)
    monkeypatch.setattr(directory_service, 'resolve_user', lambda username: 'original-native@auth.local')
    monkeypatch.setattr(directory_service, 'group_owner', lambda: 'cfadmin@etech.com')
    delta = Mock(return_value=result)
    monkeypatch.setattr(directory_service, 'sync_user_id', delta)
    registry = object()
    assert directory_service.sync_user('original-native@auth.local', registry=registry) == expected
    delta.assert_called_once_with('uid-42', dry_run=False, registry=registry)
    source.groups_for_user.assert_not_called()


def test_conflicting_uid_in_other_group_is_quarantined_while_healthy_uid_runs(monkeypatch, directory_service):
    entries = snapshot.validate([
        {'external_id': 'a', 'name': 'A', 'member_user_ids': ['123'],
         'member_identities': [{'user_id': '123', 'employee_no': 'emp-a'}]},
        {'external_id': 'b', 'name': 'B', 'member_user_ids': ['123'],
         'member_identities': [{'user_id': '123', 'employee_no': 'emp-b'}]},
        {'external_id': 'c', 'name': 'C', 'member_user_ids': ['456'],
         'member_identities': [{'user_id': '456', 'employee_no': 'healthy'}]}])
    calls = []
    def resolve(pairs):
        calls.extend(pairs)
        return {'456': 'healthy@auth.local'}
    monkeypatch.setattr(directory_service, 'resolve_eap_pairs', resolve)
    resolved, missing, quarantined = directory_service._resolve_members(entries)
    assert calls == [{'user_id': '456', 'employee_no': 'healthy'}]
    assert [row['members'] for row in resolved] == [[], [], ['healthy@auth.local']]
    assert quarantined == {'a', 'b'}
    assert missing
