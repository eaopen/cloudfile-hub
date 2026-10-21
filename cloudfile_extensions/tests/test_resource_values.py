"""Stored resource contract cases; execution deferred until feature completion."""
import unittest
from unittest.mock import Mock

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.resources.store import ResourceStore


class ResourceValuesTest(unittest.TestCase):
    reference = dict(repo_id="11111111-1111-4111-8111-111111111111", path="/file", kind="file")
    row = ("22222222-2222-4222-8222-222222222222", "/file", "lifecycle", 1, None, None)

    def test_storage_requires_transactional_full_indexes(self):
        primary = (("uid", 0, None),)
        location = (("repo_id", 1, None), ("path_hash", 1, None), ("kind", 1, None))
        cursor = Mock()
        cursor.fetchall.side_effect = [(), (("InnoDB",),), primary, location]
        ResourceStore._storage(cursor)
        for engine, pk, lookup in ((("MyISAM",), primary, location),
                (("InnoDB",), (("uid", 0, 8),), location),
                (("InnoDB",), primary, location + (("state", 1, None),)),
                (("InnoDB",), primary, location[:-1])):
            cursor.fetchall.side_effect = [(), (engine,), pk, lookup]
            with self.assertRaises(ContractError) as raised:
                ResourceStore._storage(cursor)
            self.assertEqual(raised.exception.status, 503)

    def test_nullable_attributes_and_unsigned_revision_boundary(self):
        value = ResourceStore._decode_row(self.reference, self.row)
        self.assertIsNone(value["description"])
        row = (*self.row[:3], 18446744073709551615, "description", "cad.v1")
        self.assertEqual(ResourceStore._decode_row(self.reference, row)["local_open_type"], "cad.v1")

    def test_corrupt_stored_values_fail_closed(self):
        for position, invalid in ((0, "not-uuid"), (1, "/other"), (2, ""),
                (3, 0), (3, True), (3, "1"), (3, 18446744073709551616),
                (4, 123), (4, "x" * 4097), (5, "cad with spaces")):
            row = list(self.row)
            row[position] = invalid
            with self.subTest(position=position, value=invalid):
                with self.assertRaises(ContractError) as raised:
                    ResourceStore._decode_row(self.reference, row)
                self.assertEqual(raised.exception.status, 503)
        directory = {**self.reference, "kind": "dir"}
        with self.assertRaises(ContractError):
            ResourceStore._decode_row(directory, (*self.row[:5], "cad.v1"))
