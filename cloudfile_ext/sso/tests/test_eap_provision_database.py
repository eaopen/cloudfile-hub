"""The live OAuth adapter must persist Profile and sub together on real MariaDB."""
import os
from pathlib import Path
import subprocess
import sys
import textwrap
import uuid

import pytest


@pytest.mark.skipif(not os.environ.get('CF_TEST_DB_PORT'), reason='isolated MariaDB required')
def test_provision_with_real_orm_preserves_accounts_and_rejects_collisions():
    import pymysql
    name = 'cf_test_oauth_' + uuid.uuid4().hex
    options = dict(host='127.0.0.1', port=int(os.environ['CF_TEST_DB_PORT']), user='root', password='')
    admin = pymysql.connect(**options, autocommit=True)
    with admin.cursor() as cursor:
        cursor.execute('CREATE DATABASE ' + name)
    try:
        # Separate process keeps the deployment-only Django configuration out of
        # the pure extension suite. Only Seafile RPC/directory I/O are replaced.
        script = textwrap.dedent('''
            import sys
            from types import SimpleNamespace as NS
            from django.conf import settings
            settings.configure(DATABASES={'default': {'ENGINE': 'django.db.backends.mysql',
                'NAME': sys.argv[1], 'HOST': '127.0.0.1', 'PORT': sys.argv[2], 'USER': 'root'}},
                INSTALLED_APPS=[], OAUTH_CREATE_UNKNOWN_USER=True, SECRET_KEY='test-only')
            import django
            django.setup()
            from django.db import models, connection
            class Profile(models.Model):
                user = models.CharField(max_length=254, unique=True)
                login_id = models.CharField(max_length=225, unique=True, null=True)
                nickname = models.CharField(max_length=64, default='')
                contact_email = models.CharField(max_length=254, null=True, unique=True)
                is_manually_set_contact_email = models.BooleanField(default=False)
                class Meta:
                    app_label = 'fixture'
            class Social(models.Model):
                username = models.CharField(max_length=254)
                provider = models.CharField(max_length=32)
                uid = models.CharField(max_length=255)
                extra_data = models.TextField()
                class Meta:
                    app_label = 'fixture'
                    unique_together = [('provider', 'uid')]
            with connection.schema_editor() as schema:
                schema.create_model(Profile)
                schema.create_model(Social)
            class Native:
                rows = {}
                fail = False
                class DoesNotExist(Exception): pass
                def __init__(self, email): self.username = email
                def set_unusable_password(self): self.password = '!'
                def save(self):
                    if self.fail: return -1
                    self.rows[self.username] = self
                    return 0
                @classmethod
                def get(cls, email):
                    if email not in cls.rows: raise cls.DoesNotExist()
                    return cls.rows[email]
            Native.objects = Native
            sys.modules['seahub.auth.models'] = NS(SocialAuthUser=Social)
            sys.modules['seahub.base.accounts'] = NS(User=Native)
            sys.modules['seahub.profile.models'] = NS(Profile=Profile)
            from cloudfile_ext.sso import directory, eap_oauth
            employee = ['1022']
            directory.active = lambda registry: NS(context_for_user_id=lambda uid:
                {'status': 'active', 'attributes': {'employee_no': employee[0]}})
            def info(uid='123', sub='s1'):
                return {'userId': uid, 'sub': sub, 'preferred_username': employee[0], 'email': ''}
            first = eap_oauth.provision('authentik', info())
            assert first.username == '1022@auth.local' and first.password == '!'
            assert Profile.objects.get(user=first.username).login_id == '123'
            assert eap_oauth.provision('authentik', info()).username == first.username
            assert Profile.objects.count() == Social.objects.count() == 1
            def rejected(data):
                try: eap_oauth.provision('authentik', data)
                except eap_oauth.IdentityConflict: return
                raise AssertionError('conflicting identity accepted')
            rejected(info('456'))  # recycled UID/sub cannot change an existing account
            rejected(info('456', 'new-sub'))  # employee-only match is insufficient
            first.is_active = False
            rejected(info())
            first.is_active = True
            employee[0] = '2000'
            old = Native('opaque@auth.local'); old.is_active = True; old.save()
            Profile.objects.create(user=old.username, login_id='2000')
            Social.objects.create(username=old.username, provider='authentik', uid='legacy', extra_data='{}')
            assert eap_oauth.provision('authentik', info('999', 'legacy')).username == old.username
            assert Profile.objects.get(user=old.username).login_id == '999'
            employee[0] = '3000'
            Native.fail = True
            rejected(info('777', 'failed'))
            assert not Profile.objects.filter(login_id='777').exists()
            assert not Social.objects.filter(uid='failed').exists()
            assert Profile.objects.count() == Social.objects.count() == 2
        ''')
        result = subprocess.run([sys.executable, '-c', script, name, str(options['port'])],
                                cwd=Path(__file__).resolve().parents[3], capture_output=True, text=True)
        assert result.returncode == 0, result.stdout + result.stderr
    finally:
        with admin.cursor() as cursor:
            cursor.execute('DROP DATABASE ' + name)
        admin.close()
