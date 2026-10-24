"""Run once after Seafile starts, or manually after an administrator change.

Not an AppConfig.ready() hook and not a per-HTTP-request permission check.
Provider errors are surfaced to the caller; Docker logs and continues startup.
"""
from contextlib import contextmanager
from uuid import uuid4

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.utils.module_loading import import_string

from cloudfile_ext.v2.admin_startup import sync_native_admins, validated_roster
from cloudfile_ext.v2.errors import IdentityUnavailable


@contextmanager
def native_identity():
    """Use native CE SQL/RPC, independent of Redis or any specific Provider."""
    import pymysql
    from seaserv import ccnet_api
    from seahub.utils.db_api import SeafileDB
    from seahub.utils.ccnet_db import get_ccnet_db_name
    from cloudfile_ext.v2.identity import NativeIdentity

    db = settings.DATABASES['default']
    connection = pymysql.connect(
        host=db.get('HOST') or 'localhost', port=int(db.get('PORT') or 3306),
        user=db['USER'], password=db['PASSWORD'],
        database=SeafileDB().db_name, autocommit=True, charset='utf8mb4',
        connect_timeout=5, read_timeout=10, write_timeout=10)
    try:
        def create_account(username):
            # External administrator accounts use nonstaff CE users with
            # noninteractive random passwords until trusted SSO authenticates.
            if ccnet_api.add_emailuser(username, uuid4().hex + uuid4().hex, 0, 1) != 0:
                raise IdentityUnavailable('native account creation failed')
        identity = NativeIdentity(
            connection, account_schema=get_ccnet_db_name(),
            hub_schema=db['NAME'],
            issuer=(getattr(settings, 'CF_DIRECTORY_URL', '') or
                    getattr(settings, 'CF_PROVIDER_ADMIN_SOURCE', '') or
                    'standalone-enterprise-directory'),
            create_account=create_account)
        yield identity
    finally:
        connection.close()


def read_provider_roster():
    source = getattr(settings, 'CF_PROVIDER_ADMIN_SOURCE', '')
    if source:
        if not isinstance(source, str):
            raise IdentityUnavailable('invalid administrator list callback')
        return import_string(source)()
    # Default adapter uses the same short-lived, machine JWT-authenticated
    # Directory channel already configured for enterprise GroupUser.
    from cloudfile_ext.v2.etech_directory import Directory
    return Directory().get('/administrators')


class Command(BaseCommand):
    help = 'Once-only startup synchronization of trusted enterprise administrators'

    def handle(self, *args, **options):
        if getattr(settings, 'CF_PROVIDER_ADMIN_STARTUP_SYNC_ENABLED', False) is not True:
            self.stdout.write('CF_ADMIN_SYNC SKIPPED (not configured)')
            return
        try:
            roster = validated_roster(
                read_provider_roster(),
                required_account=getattr(settings, 'CF_PROVIDER_ADMIN_EXPECTED_ACCOUNT', ''))
            with native_identity() as identity:
                managed_accounts = tuple(filter(None, (name.strip() for name in
                    getattr(settings, 'CF_PROVIDER_ADMIN_MANAGED_ACCOUNTS', '').split(','))))
                outcome = sync_native_admins(identity, roster, managed_accounts=managed_accounts)
        except Exception as error:
            # Do not log personal data, service tokens or full error payloads.
            raise CommandError('CF_ADMIN_SYNC FAILED: ' + type(error).__name__) from error
        self.stdout.write('CF_ADMIN_SYNC APPLIED added=%d removed=%d unchanged=%d'
                          % (outcome['added'], outcome['removed'], outcome['kept']))
