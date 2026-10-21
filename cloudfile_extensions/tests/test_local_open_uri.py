"""Pure URI injection/paired-origin contract, not actual session consumption."""
import unittest

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.local_edit.open_uri import OpenURI, make_open_uri, parse_open_uri


class LocalOpenURITests(unittest.TestCase):
    def setUp(self):
        self.value = OpenURI("https://cloudfile.invalid", "11111111-1111-4111-8111-111111111111", "A" * 43)
        self.paired = frozenset({self.value.instance})
        self.uri = make_open_uri(self.value)

    def test_exact_canonical_uri_roundtrip_without_ticket_repr(self):
        self.assertEqual(parse_open_uri(self.uri, paired_instances=self.paired), self.value)
        self.assertNotIn(self.value.ticket, repr(self.value))

    def test_unknown_origin_never_auto_pairs(self):
        with self.assertRaises(ContractError) as error:
            parse_open_uri(self.uri, paired_instances=frozenset({"https://other.invalid"}))
        self.assertNotIn(self.value.ticket, str(error.exception))

    def test_duplicate_options_commands_and_fragments_are_rejected(self):
        for raw in (self.uri + "&command=calc.exe", self.uri + "&ticket=" + self.value.ticket,
                self.uri + "#fragment", self.uri.replace("//v1/", "//v1@foreign.invalid/"),
                self.uri.replace("/open?", "/edit?"), self.uri + " --admin", self.uri.replace("%3A", "%")):
            with self.assertRaises(ContractError):
                parse_open_uri(raw, paired_instances=self.paired)

    def test_noncanonical_double_encoding_and_oversize_are_rejected(self):
        for raw in (self.uri.replace("%3A", "%253A"), self.uri.replace("%3A", "%3a"),
                self.uri.replace("instance=", "instance=%20"), "x" * 2049):
            with self.assertRaises(ContractError):
                parse_open_uri(raw, paired_instances=self.paired)
