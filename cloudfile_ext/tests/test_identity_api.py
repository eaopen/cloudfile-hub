from types import SimpleNamespace
from cloudfile_ext.identity import unique_identity, AmbiguousSubject, provisioning_provider, provisioning_enabled


def test_provisioning_gate_preserves_legacy_and_requires_native_admin_opt_in():
    assert not provisioning_enabled(SimpleNamespace())
    assert provisioning_enabled(SimpleNamespace(ENABLE_OAUTH=True))
    assert provisioning_enabled(SimpleNamespace(ENABLE_CUSTOM_OAUTH=True))
    assert not provisioning_enabled(SimpleNamespace(CLOUDFILE_OIDC_ENABLED=True))
    assert not provisioning_enabled(SimpleNamespace(CLOUDFILE_ADMIN_POLICY_ENABLED=True))
    assert provisioning_enabled(SimpleNamespace(ENABLE_OAUTH=False,
        CLOUDFILE_OIDC_ENABLED=True, CLOUDFILE_ADMIN_POLICY_ENABLED=True))


def test_directory_provisioning_does_not_reuse_oauth_namespace():
    assert provisioning_provider('etech-directory', 'authentik:dev') == 'directory:etech'
    assert provisioning_provider(None, 'authentik:dev') == 'authentik:dev'
    assert provisioning_provider('', 'authentik:dev') == 'authentik:dev'
    try:
        provisioning_provider('unknown', 'authentik:dev')
    except ValueError:
        pass
    else:
        raise AssertionError('unknown identity sources must be refused')


def test_external_id_resolution_requires_one_native_identity():
    assert unique_identity([]) is None
    assert unique_identity(['opaque@auth.local', 'opaque@auth.local']) == 'opaque@auth.local'
    try:
        unique_identity(['first@auth.local', 'second@auth.local'])
    except AmbiguousSubject:
        pass
    else:
        raise AssertionError('ambiguous provider bindings must be rejected')
