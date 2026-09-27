"""Bounded streaming orchestration, not real session/file authorization proof."""
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from cloudfile_extensions.identity.session_stream import OIDCSessionStream
from cloudfile_extensions.identity.session_authority import OIDCSessionAuthority
from cloudfile_extensions.identity.native_session import SESSION_REFERENCE_KEY
from cloudfile_extensions.common.errors import ContractError


class CloseableSource:
    def __init__(self, values=()):
        self.values = iter(values)
        self.close = Mock()

    def __iter__(self):
        return self

    def __next__(self):
        return next(self.values)


class SessionStreamTests(unittest.TestCase):
    def setUp(self):
        self.authority = Mock(spec=OIDCSessionAuthority)
        self.session = Mock()
        self.session.session_key = "a" * 32
        self.session.get.return_value = {"scope_hash": "fixture"}
        self.request = SimpleNamespace(session=self.session)

    def test_splits_chunks_and_rechecks_each_release(self):
        value = b"a" * (OIDCSessionStream.BLOCK + 1)
        stream = OIDCSessionStream(iter([b"", value]), self.authority, self.request)
        self.assertEqual(list(stream), [value[:-1], value[-1:]])
        self.assertEqual(self.authority.check.call_count, 2)
        self.assertTrue(stream.closed)

    def test_revocation_after_first_chunk_stops_and_closes_source(self):
        source = Mock()
        source.__iter__ = Mock(return_value=source)
        source.__next__ = Mock(side_effect=[b"first", b"private"])
        stream = OIDCSessionStream(source, self.authority, self.request)
        self.assertEqual(next(stream), b"first")
        self.authority.check.side_effect = ContractError("AUTHENTICATION_REQUIRED", "Ended", 401)
        with self.assertRaises(ContractError):
            next(stream)
        source.close.assert_called_once()
        with self.assertRaises(StopIteration):
            next(stream)

    def test_changed_session_and_oversize_input_never_release(self):
        stream = OIDCSessionStream(iter([b"private"]), self.authority, self.request)
        self.session.session_key = "b" * 32
        with self.assertRaises(ContractError):
            next(stream)
        self.authority.check.assert_not_called()
        stream = OIDCSessionStream(iter([b"x" * (OIDCSessionStream.MAX_SOURCE_CHUNK + 1)]), self.authority, self.request)
        with self.assertRaises(ContractError):
            next(stream)

    def test_early_close_releases_unconsumed_source_once(self):
        source = CloseableSource()
        stream = OIDCSessionStream(source, self.authority, self.request)
        stream.close()
        stream.close()
        source.close.assert_called_once()
