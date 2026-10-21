"""Adapter fixtures only; these do not prove native guards or real SQL."""
from contextlib import contextmanager
from unittest import TestCase
from unittest.mock import Mock, patch

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.search.publication_reader import SearchPublicationReader


class PublicationReaderTest(TestCase):
    REPO = "11111111-1111-4111-8111-111111111111"
    REVISION = "22222222-2222-4222-8222-222222222222"

    def reader(self, row):
        connection, sql = Mock(), Mock()
        connection.get_autocommit.return_value = True
        sql.fetchone.return_value = row

        @contextmanager
        def owned(store, generation, index):
            self.assertIs(store.connection, connection)
            self.assertEqual((generation, index), ("g2", "private_g2"))
            yield sql

        reader = SearchPublicationReader(connection_factory=lambda: connection,
            generation="g2", index="private_g2", policy_reader=lambda repo: "policy7")
        return reader, connection, owned

    def test_published_revision_is_part_of_cursor_version(self):
        reader, connection, owned = self.reader(("g2", self.REVISION))
        with patch("cloudfile_extensions.search.publication_reader.SchemaRunner"), patch(
                "cloudfile_extensions.search.publication_reader.SearchRebuildStore._owned", owned):
            self.assertEqual(reader(self.REPO), dict(policy_revision="policy7",
                index_generation="g2:" + self.REVISION, ready=True))
        connection.close.assert_called_once()

    def test_missing_or_different_publication_fails_closed(self):
        for row in (None, ("g3", self.REVISION), ("g2", "invalid")):
            reader, connection, owned = self.reader(row)
            with patch("cloudfile_extensions.search.publication_reader.SchemaRunner"), patch(
                    "cloudfile_extensions.search.publication_reader.SearchRebuildStore._owned", owned):
                with self.assertRaises(ContractError):
                    reader(self.REPO)
            connection.close.assert_called_once()

    def test_foreign_transaction_is_not_closed_or_rolled_back(self):
        reader, connection, _ = self.reader(("g2", self.REVISION))
        connection.get_autocommit.return_value = False
        with self.assertRaises(ContractError):
            reader(self.REPO)
        connection.close.assert_not_called()
        connection.rollback.assert_not_called()
