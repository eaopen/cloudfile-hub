"""Native management works without a browser identity runtime or extra settings."""
from types import SimpleNamespace
from unittest.mock import Mock, patch
import pytest
from cloudfile_extensions.authorization.admin_management import NativeAdministratorResources
from cloudfile_extensions.capabilities import administrator_policy_implementation_registry, build_capability_document
from cloudfile_extensions.registry import ImplementationRegistry


def test_native_admin_uses_existing_mysql_settings_and_private_transaction():
    settings = SimpleNamespace(DATABASES={'default': {'NAME': 'existing_hub'}}, CF_NATIVE_DATABASE_NAME='existing_accounts')
    database = Mock(vendor='mysql')
    wrapper = database.copy.return_value
    cursor = Mock()
    wrapper.connection.cursor.return_value.__enter__ = Mock(return_value=cursor)
    wrapper.connection.cursor.return_value.__exit__ = Mock(return_value=False)
    with patch('django.conf.settings', settings), patch('django.db.connections', {'cloudfile': database}), patch('cloudfile_ext.db_router._alias', return_value='cloudfile'), patch('cloudfile_extensions.schema.runner.SchemaRunner') as schema:
        resources = NativeAdministratorResources()
        assert resources.native_schema == 'existing_accounts'
        assert resources.identity_schema == 'existing_hub'
        with resources.connection() as connection:
            assert connection is wrapper.connection
        schema.return_value.require_current.assert_called_once()
        wrapper.set_autocommit.assert_called_once_with(True)
        wrapper.close.assert_called_once()
        cursor.execute.assert_called_once_with('SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ')


def test_native_admin_closes_connection_when_schema_is_not_ready():
    resource = object.__new__(NativeAdministratorResources)
    resource.database = Mock()
    wrapper = resource.database.copy.return_value
    wrapper.connection.cursor.return_value.__enter__ = Mock()
    wrapper.connection.cursor.return_value.__exit__ = Mock(return_value=False)
    with patch('cloudfile_extensions.schema.runner.SchemaRunner') as schema:
        schema.return_value.require_current.side_effect = ValueError('schema not ready')
        with pytest.raises(ValueError):
            with resource.connection():
                pytest.fail('must not run policy commands')
    wrapper.close.assert_called_once()


def test_admin_capability_does_not_require_oidc_but_never_advertises_unready_storage():
    for ready in (True, False):
        registry = administrator_policy_implementation_registry(ImplementationRegistry(), None, enabled=True, native_ready=lambda: ready)
        assert build_capability_document(implementation_registry=registry)['capabilities']['directory.acl.manage']['enabled'] is ready
