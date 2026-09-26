"""Tag contract coverage, execution deferred until feature completion."""
import unittest
from uuid import uuid4

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.tags.definitions import user_definition, system_definition, definition_changes, decode


class TagDefinitionTest(unittest.TestCase):
    def test_user_normalization_case_and_trusted_namespace(self):
        repo, tag = str(uuid4()), str(uuid4())
        value = user_definition(repo, tag, dict(label="  e\u0301  ", color="#aBc123"))
        self.assertEqual(value["label"], "é")
        self.assertEqual(value["normalized_label"], "é")
        self.assertEqual(value["color"], "#ABC123")
        self.assertEqual(value["namespace"], "user:" + repo)
        self.assertNotEqual(user_definition(repo, tag, dict(label="A"))["label"],
                            user_definition(repo, tag, dict(label="a"))["label"])
        with self.assertRaises(ContractError):
            user_definition(repo, tag, dict(label="name", kind="system"))

    def test_system_fallback_and_immutable_source_patch(self):
        tag = str(uuid4())
        value = system_definition(tag, provider="source", namespace="classification", code="drawing", value={})
        self.assertEqual(value["label"], "drawing")
        self.assertIsNone(value["normalized_label"])
        self.assertEqual(definition_changes(dict(enabled=False)), dict(enabled=False))
        for changes in ({"namespace": "other"}, {"kind": "system"}, {"enabled": 1}, {"color": "red"}, {"label": "<b>"}):
            with self.assertRaises(ContractError):
                definition_changes(changes)
        with self.assertRaises(ContractError):
            system_definition(tag, provider="source", namespace="user:other", code="drawing", value={})

    def test_disabled_stored_binding_definition_remains_visible(self):
        tag, repo, revision = str(uuid4()), str(uuid4()), str(uuid4())
        value = decode((tag, "user", "cloudfile", "user:" + repo, tag, "drawing", "drawing", None, 0, repo, revision))
        self.assertFalse(value["enabled"])
        self.assertEqual(value["etag"], '"' + revision + '"')
