"""Pure account naming shared by trusted login and administrator provisioning."""
import re


def account_username(account):
    """Follow CE's lowercase account naming; never select by contact email."""
    if (not isinstance(account, str) or not re.fullmatch(r'[A-Za-z0-9._-]{1,200}', account)
            or account.lower() == 'cfadmin'):
        raise ValueError('valid non-reserved Directory account required')
    # ccnet_user_manager_add_emailuser lowercases usernames in native RPC.
    # Normalize creation in SQL JIT too; stored UID owners are never renamed.
    return account.lower() + '@auth.local'
