"""Pure account naming shared by trusted login and administrator provisioning."""
import re


def account_username(account):
    """Preserve the Directory account; never choose identity by contact email."""
    if (not isinstance(account, str) or not re.fullmatch(r'[A-Za-z0-9._-]{1,200}', account)
            or account.lower() == 'cfadmin'):
        raise ValueError('valid non-reserved Directory account required')
    return account + '@auth.local'
