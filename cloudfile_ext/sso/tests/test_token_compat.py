"""Legacy transport compatibility must never widen identity selection."""
import pytest
from cloudfile_ext.sso.token_compat import normalize_token_identity


def test_default_off_preserves_native_transport():
    value = '10220942@shanghai-electric.com'
    assert normalize_token_identity(value) == (value, False)


@pytest.mark.parametrize('value', ['10220942@auth.local', '10220942@other.com',
    '10220942@shanghai-electric.com.evil', None])
def test_only_exact_configured_domain_is_adapted(value):
    assert normalize_token_identity(value, 'shanghai-electric.com') == (value, False)


@pytest.mark.parametrize('account', ['cfadmin', 'name', ' admin', '1@2', '１２３', '1' * 33])
def test_unsupported_legacy_accounts_are_rejected(account):
    with pytest.raises(ValueError):
        normalize_token_identity(account + '@shanghai-electric.com', 'shanghai-electric.com')


@pytest.mark.parametrize('domain', [True, 'SHANGHAI-ELECTRIC.COM', '@shanghai-electric.com', '*'])
def test_invalid_operator_domain_is_rejected(domain):
    with pytest.raises(ValueError):
        normalize_token_identity('10220942@shanghai-electric.com', domain)
