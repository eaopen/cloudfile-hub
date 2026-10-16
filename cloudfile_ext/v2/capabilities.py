"""One discovery contract for the fresh V2 runtime, without legacy imports."""


def capability_document():
    # DDL and isolated identity helpers are not installed HTTP/data-plane
    # features. Keep them unavailable until their actual request paths exist.
    names = (
        'auth.oidc', 'identity.users.resolve', 'directory.subjects',
        'directory.groups.manage', 'library.policy', 'library.shares.manage',
        'directory.acl', 'directory.acl.manage', 'directory.acl.effective',
        'directory.shares', 'local.open-edit', 'audit.query',
    )
    return {
        'product': 'CloudFile',
        'version': '2.0.0-dev',
        'contract_version': '1.0',
        'capabilities': {name: {'enabled': False} for name in names},
    }
