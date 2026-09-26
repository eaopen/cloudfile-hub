"""ORM transaction tests using native-shaped fixtures, not a live CE runtime."""
import subprocess
import sys
import textwrap
import unittest
from unittest.mock import Mock


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
        script = textwrap.dedent('''
            from contextlib import nullcontext
            from django.conf import settings
            settings.configure(INSTALLED_APPS=[], DATABASES={"default": {
                "ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}})
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
        result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
