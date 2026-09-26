"""Issuance request boundaries only; trusted service authorization tested separately."""
import json
import unittest

from django.test import RequestFactory

from cloudfile_extensions.identity.delegation_issue_http import UserDelegationIssueView


class DelegationIssueHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from django.conf import settings
        if not settings.configured:
            settings.configure(SECRET_KEY="fixture-only", ALLOWED_HOSTS=["testserver"], DEFAULT_CHARSET="utf-8")
        import django
        django.setup()

    def setUp(self):
        self.requests = RequestFactory()
        self.view = UserDelegationIssueView.as_view()
        self.body = dict(userId="actual-login-user", reference=dict(
            repo_id="11111111-1111-1111-1111-111111111111", path="/file", kind="file"))

    def request(self, body=None, **headers):
        options = dict(HTTP_AUTHORIZATION="Bearer fixture-machine")
        options.update(headers)
        return self.requests.post("/delegations/", data=json.dumps(self.body) if body is None else body,
            content_type="application/json", secure=True, **options)

    def test_forbidden_credential_and_state_inputs(self):
        for headers in (dict(HTTP_COOKIE=""), dict(HTTP_COOKIE="sessionid=fixture"),
                dict(HTTP_CONTENT_ENCODING="gzip")):
            with self.subTest(headers=headers):
                self.assertEqual(self.view(self.request(**headers)).status_code, 400)
        for field in ("provider", "epoch", "context_epoch", "expires_in", "kid", "secret"):
            with self.subTest(field=field):
                self.assertEqual(self.view(self.request(json.dumps(dict(self.body, **{field: "untrusted"})))).status_code, 400)

    def test_subject_must_be_business_string_and_action_read_only(self):
        for changes in (dict(userId=1), dict(userId=""), dict(operation="upload"),
                dict(reference=dict(self.body["reference"], kind="dir"))):
            with self.subTest(changes=changes):
                self.assertEqual(self.view(self.request(json.dumps(dict(self.body, **changes)))).status_code, 400)

    def test_duplicate_and_budget(self):
        self.assertEqual(self.view(self.request('{"userId":"a","userId":"b","reference":{}}')).status_code, 400)
        self.assertEqual(self.view(self.request(" " * 16385)).status_code, 413)

    def test_missing_runtime_is_not_issuance_success(self):
        response = self.view(self.request())
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("delegation", json.loads(response.content))
        self.assertIn("no-store", response["Cache-Control"])
        self.assertEqual(response["Vary"], "Authorization")
