"""ORM transaction tests using native-shaped fixtures, not a live CE runtime."""
import subprocess
import json
import os
import sys
import textwrap
import unittest
from unittest.mock import Mock
from cloudfile_extensions.tests.test_schema import DatabaseTestCase


class IdentityBindingTests(unittest.TestCase):
    def test_unique_lookup_rejects_duplicates_and_sanitizes_database_errors(self):
        from django.core.exceptions import MultipleObjectsReturned, ObjectDoesNotExist
        from django.db import OperationalError
        from cloudfile_extensions.identity.bindings import unique_binding
        from cloudfile_extensions.common.errors import ContractError
        query = Mock()
        query.get.side_effect = ObjectDoesNotExist()
        self.assertIsNone(unique_binding(query, uid="subject"))
        for error, status in ((MultipleObjectsReturned("private accounts"), 409),
                              (OperationalError("private database address"), 503)):
            query.get.side_effect = error
            with self.assertRaises(ContractError) as caught:
                unique_binding(query, uid="subject")
            self.assertEqual(caught.exception.status, status)
            self.assertNotIn("private", caught.exception.message)

    def test_binding_conflicts_disabled_accounts_and_audit_rollback(self):
        self._run_binding_checks()

    def _run_binding_checks(self, database=None):
        script = textwrap.dedent('''
            from contextlib import nullcontext
            import json, os
            from django.conf import settings
            settings.configure(INSTALLED_APPS=[], DATABASES={"default": json.loads(
                os.environ["CF_BINDING_FIXTURE_DATABASE"])})
            import django
            django.setup()
            from django.db import models, connection
            from cloudfile_extensions.identity.bindings import IdentityBindings
            from cloudfile_extensions.common.errors import ContractError
            class Profile(models.Model):
                user = models.CharField(max_length=255, unique=True)
                login_id = models.CharField(max_length=225, null=True, unique=True)
                class Meta: app_label = "fixture"
            class Social(models.Model):
                username = models.CharField(max_length=255)
                provider = models.CharField(max_length=32)
                uid = models.CharField(max_length=255)
                extra_data = models.TextField()
                class Meta:
                    app_label = "fixture"
                    unique_together = (("provider", "uid"),)
            with connection.schema_editor() as editor:
                editor.create_model(Profile)
                editor.create_model(Social)
            Profile.objects.create(user="native-one")
            Profile.objects.create(user="native-two")
            facts = []
            bindings = IdentityBindings(profiles=Profile, social_users=Social,
                account_active=lambda username: username != "disabled",
                guard=lambda *args: nullcontext(), audit=facts.append)
            args = dict(issuer="https://issuer.example/", subject="s1", user_id="u1",
                username="native-one", actor="admin", reason="verified migration mapping")
            assert bindings.prebind(**args) == ("native-one", True)
            assert bindings.prebind(**args) == ("native-one", False)
            assert len(facts) == 1
            assert bindings.resolve(issuer=args["issuer"], subject="s1", user_id="u1") == "native-one"
            if connection.vendor == "mysql":
                # The fixture deliberately uses a case-insensitive collation.
                # An ORM match must still not authenticate a different identity.
                with connection.cursor() as cursor:
                    cursor.execute("ALTER TABLE fixture_social MODIFY uid VARCHAR(255) COLLATE utf8mb4_general_ci NOT NULL")
                    cursor.execute("ALTER TABLE fixture_profile MODIFY login_id VARCHAR(225) COLLATE utf8mb4_general_ci NULL")
                for changed in ({"subject": "S1"}, {"user_id": "U1"}):
                    try: bindings.resolve(**{ "issuer": args["issuer"], "subject": "s1", "user_id": "u1", **changed})
                    except ContractError as error: assert error.status == 409
                    else: raise AssertionError("collation identity alias accepted")
            for changes in ({"username": "native-two"}, {"user_id": "u2"},
                            {"subject": "s2", "username": "native-two"}):
                try: bindings.prebind(**{**args, **changes})
                except ContractError as error: assert error.status == 409
                else: raise AssertionError("conflict accepted")
            assert bindings.resolve(issuer=args["issuer"], subject="missing", user_id="u1") is None
            bindings.account_active = lambda username: False
            try: bindings.resolve(issuer=args["issuer"], subject="s1", user_id="u1")
            except ContractError as error: assert error.status == 403
            else: raise AssertionError("disabled identity accepted")
            bindings.account_active = lambda username: True
            def failed_audit(event): raise RuntimeError("fixture audit failure")
            bindings.audit = failed_audit
            try: bindings.prebind(**{**args, "subject": "s2", "user_id": "u2", "username": "native-two"})
            except RuntimeError: pass
            else: raise AssertionError("audit failure ignored")
            assert Profile.objects.get(user="native-two").login_id is None
            assert Social.objects.count() == 1
            if connection.vendor == "mysql":
                # Emulate a damaged legacy unique index in this random schema
                # only. Real duplicate rows must be rejected, not first-picked.
                with connection.schema_editor() as editor:
                    editor.alter_unique_together(Social, {("provider", "uid")}, set())
                original = Social.objects.get()
                Social.objects.create(username=original.username, provider=original.provider,
                    uid=original.uid, extra_data=original.extra_data)
                for operation in (
                    lambda: bindings.resolve(issuer=args["issuer"], subject="s1", user_id="u1"),
                    lambda: bindings.prebind(**args),
                ):
                    try: operation()
                    except ContractError as error: assert error.status == 409
                    else: raise AssertionError("duplicate binding accepted")
            # Actual ORM database failure, not an adapter mock: unavailable
            # identity storage cannot be confused with an unbound/new user.
            with connection.schema_editor() as editor:
                editor.delete_model(Social)
            for operation in (
                lambda: bindings.resolve(issuer=args["issuer"], subject="s1", user_id="u1"),
                lambda: bindings.prebind(**{**args, "subject": "s2", "user_id": "u2", "username": "native-two"}),
            ):
                try: operation()
                except ContractError as error:
                    assert error.status == 503
                    assert "fixture_social" not in error.message
                else: raise AssertionError("unavailable identity storage accepted")
            assert Profile.objects.get(user="native-two").login_id is None
        ''')
        environment = {**os.environ, "CF_BINDING_FIXTURE_DATABASE": json.dumps(database or {
            "ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"})}
        result = subprocess.run([sys.executable, "-c", script], env=environment,
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class MySQLIdentityBindingTests(DatabaseTestCase):
    def test_real_mysql_binding_constraints_collation_and_rollback(self):
        IdentityBindingTests._run_binding_checks(self, {
            "ENGINE": "django.db.backends.mysql", "NAME": self.database,
            "HOST": self.options["host"], "PORT": self.options["port"],
            "USER": "root", "PASSWORD": "", "OPTIONS": {"charset": "utf8mb4"},
        })
