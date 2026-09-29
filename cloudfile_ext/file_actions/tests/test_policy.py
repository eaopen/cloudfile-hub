# -*- coding: utf-8 -*-

from cloudfile_ext.file_actions import policy


PREVIEW = ('pdf', 'txt', 'docx')
def by_id(actions):
    return {action['id']: action for action in actions}


def test_extension_normalization():
    assert policy.extension('/Drawings/PLAN.DWG') == 'dwg'
    assert policy.extension('/readme') == ''


def test_all_features_off_is_quiet():
    assert policy.actions_for('/plan.docx', {}, PREVIEW) == []


def test_preview_is_read_only_and_does_not_need_locking():
    actions = by_id(policy.actions_for(
        '/plan.pdf', {'CF_ENABLE_FILE_PREVIEW': True}, PREVIEW))
    assert actions[policy.NATIVE_PREVIEW]['available'] is True
    assert actions[policy.NATIVE_PREVIEW]['writes'] is False


def test_onlyoffice_is_not_a_cloudfile_action():
    assert policy.actions_for('/plan.docx', {
        'CF_ENABLE_ONLYOFFICE': True,
    }, PREVIEW) == []


def test_local_view_is_available_but_local_edit_and_checkout_are_not():
    actions = by_id(policy.actions_for('/assembly.step', {
        'CF_ENABLE_LOCAL_APP': True,
        'CF_ENABLE_CHECKOUT': True,
    }, PREVIEW))
    assert actions[policy.LOCAL_VIEW]['available'] is True
    assert actions[policy.LOCAL_EDIT]['available'] is False
    assert actions[policy.CHECKOUT]['available'] is False


def test_checkout_activates_after_server_provider_is_ready():
    actions = by_id(policy.actions_for('/plan.docx', {
        'CF_ENABLE_LOCAL_APP': True,
        'CF_ENABLE_CHECKOUT': True,
    }, PREVIEW, lock_provider_ready=True))
    assert actions[policy.CHECKOUT]['available'] is True
    assert actions[policy.LOCAL_EDIT]['available'] is True


def test_read_only_user_never_sees_a_write_action_as_available():
    actions = by_id(policy.actions_for('/assembly.step', {
        'CF_ENABLE_LOCAL_APP': True,
        'CF_ENABLE_CHECKOUT': True,
    }, PREVIEW, lock_provider_ready=True, can_edit=False))
    assert actions[policy.LOCAL_VIEW]['available'] is True
    assert actions[policy.LOCAL_EDIT]['available'] is False
    assert actions[policy.CHECKOUT]['available'] is False
    assert actions[policy.LOCAL_EDIT]['reason'] == 'edit_permission_required'
