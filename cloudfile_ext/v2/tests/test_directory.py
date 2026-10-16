"""Directory subject reads: one exact-UID fetch, no fallback, fail closed."""
import json
import unittest
from unittest.mock import patch

from cloudfile_ext.v2 import directory
from cloudfile_ext.v2.directory import DirectorySubjectClient, trusted_url
from cloudfile_ext.v2.errors import IdentityUnavailable


class FakeResponse:
    def __init__(self, status, body):
        self.status, self._body = status, body

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        return False

    def read(self, size=-1):
        return self._body if size is None or size < 0 else self._body[:size]


class FakeOpener:
    def __init__(self, result):
        self.result, self.calls = result, []

    def open(self, request, timeout=None):
        self.calls.append((request, timeout))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def client(result, **kwargs):
    opener = FakeOpener(result)
    return DirectorySubjectClient('https://directory.example.test/directory', lambda: 'machine-token',
                                  opener=opener, **kwargs), opener


class DirectoryClientTest(unittest.TestCase):
    def test_exact_uid_is_requested_with_the_machine_credential(self):
        subject = {'userId': 'uid-1'}
        probe, opener = client(FakeResponse(200, json.dumps(subject).encode()))
        self.assertEqual(probe.fetch('uid-1'), subject)
        request, timeout = opener.calls[0]
        self.assertEqual(request.full_url, 'https://directory.example.test/directory/users/uid-1/context')
        self.assertEqual(request.get_header('Authorization'), 'Bearer machine-token')
        self.assertEqual(request.get_header('Cache-control'), 'no-store')
        self.assertEqual(timeout, 5)
        self.assertEqual(probe('uid-1'), subject)

    def test_uid_is_path_quoted_and_traversal_segments_are_refused(self):
        probe, opener = client(FakeResponse(200, b'{}'))
        probe.fetch('uid/../other')
        self.assertEqual(opener.calls[0][0].full_url,
                         'https://directory.example.test/directory/users/uid%2F..%2Fother/context')
        for uid in ('.', '..', ''):
            with self.subTest(uid=uid), self.assertRaises(IdentityUnavailable):
                probe.fetch(uid)

    def test_status_redirect_and_transport_failures_are_unavailable(self):
        for result in (FakeResponse(404, b'{}'), FakeResponse(503, b'{}'),
                       FakeResponse(302, b''), FakeResponse(None, b'{}'),
                       directory.HTTPError('https://directory.example.test/', 302, 'Found', {}, None),
                       directory.URLError('unreachable'), TimeoutError('slow')):
            with self.subTest(result=result), self.assertRaises(IdentityUnavailable):
                client(result)[0].fetch('uid-1')

    def test_invalid_or_oversized_body_is_unavailable(self):
        for body in (b'not json', b'[]', b'"text"', b'\xff\xfe'):
            with self.subTest(body=body), self.assertRaises(IdentityUnavailable):
                client(FakeResponse(200, body))[0].fetch('uid-1')
        with patch.object(directory, 'MAXIMUM_RESPONSE', 8):
            with self.assertRaises(IdentityUnavailable):
                client(FakeResponse(200, b'{"a": 1, "b": 2}'))[0].fetch('uid-1')

    def test_trusted_url_rejects_untrusted_origins(self):
        self.assertEqual(trusted_url('https://directory.example.test/directory/'),
                         'https://directory.example.test/directory')
        for value in ('', 'file:///etc/passwd', 'http://directory.example.test/',
                      'https://user:pass@directory.example.test/', 'https://directory.example.test/?a=1',
                      'https://directory.example.test/#fragment', 'https:///context',
                      'https://[invalid/directory'):
            with self.subTest(value=value), self.assertRaises(IdentityUnavailable):
                trusted_url(value)
        self.assertEqual(trusted_url('http://127.0.0.1:8080/d', insecure=True), 'http://127.0.0.1:8080/d')

    def test_bounded_timeout_is_required(self):
        for timeout in (0, 31, True, '5'):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                DirectorySubjectClient('https://directory.example.test/', lambda: 'token', timeout=timeout)


if __name__ == '__main__':
    unittest.main()
