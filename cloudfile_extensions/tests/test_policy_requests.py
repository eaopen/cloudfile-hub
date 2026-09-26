"""Saved response validation; execution deferred with the overall test run."""
import json
import unittest
from uuid import uuid4

from cloudfile_extensions.authorization.requests import response
from cloudfile_extensions.authorization.rules import rule_value


class PolicyResponseTest(unittest.TestCase):
    def setUp(self):
        self.ref = dict(repo_id=str(uuid4()), path="/parts", kind="dir")
        self.value = dict(path="/parts", kind="dir", permission="r", inherit=False,
            subject=dict(type="user", provider="directory", namespace="user", external_id="u1"))
        revision = str(uuid4())
        self.result = dict(id=str(uuid4()), repo_id=self.ref["repo_id"], **self.value,
            revision=revision, etag='"' + revision + '"')

    def read(self, result):
        return response(json.dumps(result), reference=self.ref, value=self.value,
            rule_id=self.result["id"], validate=rule_value)

    def test_exact_response_and_invalid_identity_revision_fields(self):
        self.assertEqual(self.read(self.result), self.result)
        for result in ({**self.result, "id": str(uuid4())},
                       {**self.result, "revision": "bad"},
                       {**self.result, "etag": '"other"'},
                       {**self.result, "permission": "rw"},
                       {**self.result, "secret": "unexpected"}):
            with self.assertRaises(ValueError):
                self.read(result)

    def test_duplicate_json_and_non_boolean_deletion_rejected(self):
        with self.assertRaises(ValueError):
            response('{"id":"a","id":"b"}', reference=self.ref,
                value=self.value, rule_id=None, validate=rule_value)
        with self.assertRaises(ValueError):
            response(json.dumps(dict(id=self.result["id"], deleted=1)), reference=self.ref,
                value=None, rule_id=self.result["id"], validate=rule_value)
