import json
from pathlib import Path
import unittest

from cloudfile_extensions.common.conditions import compare_if_match, compare_revision
from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.common.pagination import CursorCodec, page_size
from cloudfile_extensions.common.validation import annotation_changes, sequence, utc_time
from cloudfile_extensions.directory.protocol import validate_subject
from cloudfile_extensions.resources.paths import is_descendant_or_equal, normalize_path


CONTRACTS = Path(__file__).resolve().parents[3] / "eap-cloudfile" / "contracts"


class PathContractTest(unittest.TestCase):
    def test_shared_path_vectors(self):
        vectors = json.loads((CONTRACTS / "acceptance-vectors.json").read_text())
        for case in vectors["path_cases"]:
            with self.subTest(case=case["id"]):
                source, expected = case["input"], case["expected"]
                if "error" in expected:
                    with self.assertRaises(ContractError) as caught:
                        normalize_path(source["path"], source["kind"], transport=source["transport"])
                    self.assertEqual(caught.exception.code, expected["error"])
                else:
                    result = normalize_path(source["path"], source["kind"], transport=source["transport"])
                    self.assertEqual(result, expected["path"])
                    if "is_descendant" in expected:
                        self.assertEqual(is_descendant_or_equal(result, source["ancestor"]), expected["is_descendant"])

    def test_double_decode_and_bad_utf8_are_not_accepted_as_traversal(self):
        self.assertEqual(normalize_path("%2Fparts%2F%252e%252e.prt", "file", transport="url_query_raw"), "/parts/%2e%2e.prt")
        for path in ("%2Fparts%FF", "%2Fparts%ZZ"):
            with self.assertRaises(ContractError):
                normalize_path(path, "file", transport="url_query_raw")


class ConditionTest(unittest.TestCase):
    def test_http_and_body_conditions_have_distinct_status(self):
        for operation, args, status in (
            (compare_if_match, (None, '"r1"'), 428),
            (compare_if_match, ('"r0"', '"r1"'), 412),
            (compare_revision, (None, "r1"), 428),
            (compare_revision, ("r0", "r1"), 409),
        ):
            with self.subTest(status=status), self.assertRaises(ContractError) as caught:
                operation(*args)
            self.assertEqual(caught.exception.status, status)
        compare_if_match('"r0", "r1"', '"r1"')
        compare_revision("版本1", "版本1")

    def test_weak_and_wildcard_conditions_cannot_blindly_overwrite(self):
        for header in ("*", 'W/"r1"', '"r1"\r\nextra'):
            with self.assertRaises(ContractError):
                compare_if_match(header, '"r1"')

    def test_annotation_patch_null_and_directory_hint_are_invalid(self):
        self.assertEqual(annotation_changes({"description": ""}, kind="dir"), {"description": ""})
        for changes, kind in (({}, "file"), ({"description": None}, "file"), ({"local_open_type": "cad.v1"}, "dir"), ({"local_open_type": "app.exe --run"}, "file")):
            with self.assertRaises(ContractError):
                annotation_changes(changes, kind=kind)

    def test_sequence_and_time_do_not_coerce_values(self):
        self.assertEqual(sequence("42"), 42)
        # Java Instant can emit nanoseconds; protocol validation must accept it.
        self.assertEqual(utc_time("2026-09-26T00:00:00.123456789Z").microsecond, 123456)
        for value in (42, True, "04", "sha256:1"):
            with self.assertRaises(ContractError):
                sequence(value)
        for value in ("2026-99-26T00:00:00Z", "2026-09-26T00:00:00+08:00",
                      "2026-09-26 00:00:00Z", "20260926T000000Z"):
            with self.assertRaises(ContractError):
                utc_time(value)


class CursorTest(unittest.TestCase):
    def setUp(self):
        self.now = 100
        self.codec = CursorCodec(b"test-secret-with-at-least-32-bytes", clock=lambda: self.now)
        self.context = {"userId": "u1", "filters": {"repo": "r1"}, "subject_epoch": "e1", "policy_revision": "p1"}

    def test_roundtrip_and_binding_to_actor_filters_and_epoch(self):
        token = self.codec.encode({"offset": 10}, context=self.context)
        self.assertEqual(self.codec.decode(token, context=self.context), {"offset": 10})
        for context in ({**self.context, "userId": "u2"}, {**self.context, "subject_epoch": "e2"}, {**self.context, "filters": {"repo": "r2"}}):
            with self.assertRaises(ContractError):
                self.codec.decode(token, context=context)

    def test_expiry_is_bounded_by_context_and_tokens_are_authenticated(self):
        token = self.codec.encode(10, context=self.context, expires_at=120)
        with self.assertRaises(ContractError):
            self.codec.decode("X" + token[1:], context=self.context)
        self.now = 120
        with self.assertRaises(ContractError):
            self.codec.decode(token, context=self.context)
        for value in (True, 101, 0, "50"):
            with self.assertRaises(ContractError):
                page_size(value)


class SubjectProtocolTest(unittest.TestCase):
    def setUp(self):
        examples = json.loads((CONTRACTS / "schema-examples.json").read_text())
        self.subject = next(case["value"] for case in examples["cases"] if case["id"] == "schema-subject-valid")
        self.allowed = {"employee_no", "display_name", "email"}

    def test_latest_typed_subject_and_disabled_are_distinct(self):
        result = validate_subject(self.subject, requested_user_id="user-1", attribute_allowlist=self.allowed)
        self.assertEqual(result["roles"][0]["external_id"], "role-1")
        disabled = {**self.subject, "status": "disabled", "roles": [], "organizations": []}
        self.assertEqual(validate_subject(disabled, requested_user_id="user-1", attribute_allowlist=self.allowed)["status"], "disabled")

    def test_wrong_identity_missing_memberships_credentials_and_duplicates_rejected(self):
        for invalid in (
            {**self.subject, "userId": "user-2"},
            {key: value for key, value in self.subject.items() if key != "roles"},
            {**self.subject, "attributes": {"password": "example-only"}},
            {**self.subject, "roles": self.subject["roles"] * 2},
        ):
            with self.assertRaises(ContractError):
                validate_subject(invalid, requested_user_id="user-1", attribute_allowlist=self.allowed)
