# -*- coding: utf-8 -*-
import pytest

from cloudfile_ext.file_actions import contracts


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


def test_external_preview_is_contract_read_only_action():
    assert contracts.EXTERNAL_PREVIEW in contracts.FILE_ACTIONS
    assert contracts.EXTERNAL_PREVIEW in contracts.READ_ACTIONS
    assert contracts.writes_content(contracts.EXTERNAL_PREVIEW) is False
