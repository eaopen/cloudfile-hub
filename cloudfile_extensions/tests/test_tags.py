"""Tag contract coverage, execution deferred until feature completion."""
import unittest
from unittest.mock import Mock
from uuid import uuid4

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.tags.definitions import user_definition, system_definition, definition_changes, decode
from cloudfile_extensions.tags.write import _definition_write


class TagDefinitionTest(unittest.TestCase):
    def test_duplicate_identity_is_conflict_without_hiding_other_sql_errors(self):
        cursor = Mock()
        cursor.execute.side_effect = Exception(1062, "private database detail")
        with self.assertRaises(ContractError) as raised:
            _definition_write(cursor, "statement", ("parameter",))
        self.assertEqual(raised.exception.code, "TAG_CONFLICT")
        self.assertNotIn("private", str(raised.exception))
        cursor.commit.assert_not_called()
        failure = Exception(1213, "deadlock")
        cursor.execute.side_effect = failure
        with self.assertRaises(Exception) as raised:
            _definition_write(cursor, "statement", ())
        self.assertIs(raised.exception, failure)

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
