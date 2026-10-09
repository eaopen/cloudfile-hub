"""Token alias resolution must use current UID proof, never email matching."""
from types import SimpleNamespace
from unittest.mock import Mock
import pytest
from cloudfile_ext.sso.identity_bridge import IdentityBridgeError
from cloudfile_ext.sso.token_identity import resolve_employee_token, TokenIdentityError


def source(context, mode='v2'):
    client = Mock(auth_mode=mode)
    client.call.return_value = context
    return SimpleNamespace(_client=lambda: client)


def context(employee='10220942', status='active'):
    return {'userId': '381', 'status': status, 'attributes': {'employee_no': employee}}


def test_opaque_account_is_preserved():
    fetch = Mock(return_value=[('381', 'opaque@auth.local')])
    assert resolve_employee_token('10220942@auth.local', source(context()), fetch) == 'opaque@auth.local'
    fetch.assert_called_once_with(['381'])


@pytest.mark.parametrize('value', [context('other'), context(status='disabled'), {}, {'userId': 381}])
def test_unverified_directory_identity_is_rejected(value):
    with pytest.raises(TokenIdentityError):
        resolve_employee_token('10220942@auth.local', source(value), lambda _: [])


def test_legacy_channel_is_rejected():
    with pytest.raises(TokenIdentityError):
        resolve_employee_token('10220942@auth.local', source(context(), 'legacy'))


@pytest.mark.parametrize('rows', [[], [('381','one@auth.local'), ('381','two@auth.local')], [('381','cfadmin@etech.com')]])
def test_missing_ambiguous_or_system_account_is_rejected(rows):
    with pytest.raises(TokenIdentityError):
        resolve_employee_token('10220942@auth.local', source(context()), lambda _: rows)


def test_employee_recycling_cannot_reuse_old_uid():
    changed = context()
    changed['userId'] = '999'
    # The old binding belongs to UID 381, so a recycled employee number must
    # fail rather than inherit that user's token or library permissions.
    with pytest.raises(IdentityBridgeError):
        resolve_employee_token('10220942@auth.local', source(changed), lambda _: [('381','old@auth.local')])
