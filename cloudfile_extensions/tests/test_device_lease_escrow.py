"""Device lease escrow must not expose a readable secret in Session snapshots."""
import hashlib
import unittest

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.local_edit.lease_escrow import encrypt, decrypt


class EscrowCryptoTests(unittest.TestCase):
    def setUp(self):
        self.params = dict(instance="https://cloudfile.example",
            session="11111111-1111-4111-8111-111111111111",
            device="22222222-2222-4222-8222-222222222222",
            actor="user-123")
        self.lease = dict(guard_id="33333333-3333-4333-8333-333333333333",
            generation="2", credential_epoch="1", base_file_id="a" * 40,
            token="b" * 64)
        self.secret = b"fixed secret for a test fixture - not production"

    def test_encryption_binds_live_session_device_and_actor(self):
        ciphertext = encrypt(self.secret, lease=self.lease, **self.params)
        self.assertNotIn(self.lease["token"].encode(), ciphertext)
        self.assertEqual(decrypt(self.secret, ciphertext, **self.params), self.lease)
        self.assertNotEqual(encrypt(self.secret, lease=self.lease, **self.params), ciphertext)
        for change in (dict(actor="intruder"), dict(device="99999999-9999-4999-8999-999999999999"),
                       dict(session="99999999-9999-4999-8999-999999999999")):
            with self.subTest(change=change), self.assertRaises(ContractError):
                decrypt(self.secret, ciphertext, **{**self.params, **change})
        with self.assertRaises(ContractError):
            decrypt(b"other" * 8, ciphertext, **self.params)

    def test_corrupted_ciphertext_does_not_return_token(self):
        sealed = bytearray(encrypt(self.secret, lease=self.lease, **self.params))
        sealed[-1] ^= 1
        with self.assertRaises(ContractError):
            decrypt(self.secret, bytes(sealed), **self.params)


if __name__ == "__main__":
    unittest.main()
