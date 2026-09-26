"""Actual cryptographic protocol cases; not device pairing/replay/ACL proof."""
import base64
from dataclasses import replace
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.local_edit.device_proof import DeviceChallenge, DevicePublicKey, verify_possession


def encode(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


class DeviceProofTests(unittest.TestCase):
    def setUp(self):
        self.private = ec.generate_private_key(ec.SECP256R1())
        numbers = self.private.public_key().public_numbers()
        self.public = DevicePublicKey.parse(dict(kty="EC", crv="P-256",
            x=encode(numbers.x.to_bytes(32, "big")), y=encode(numbers.y.to_bytes(32, "big"))))
        self.challenge = DeviceChallenge(instance="https://cloudfile.invalid",
            device_id="11111111-1111-4111-8111-111111111111",
            session_id="22222222-2222-4222-8222-222222222222", operation="claim",
            nonce=encode(b"n" * 32), issued_at=100, expires_at=160, request_sha256="a" * 64)
        r, s = decode_dss_signature(self.private.sign(self.challenge.message(), ec.ECDSA(hashes.SHA256())))
        self.signature = encode(r.to_bytes(32, "big") + s.to_bytes(32, "big"))

    def test_actual_p256_signature_accepts_exact_server_challenge(self):
        self.assertIsNone(verify_possession(self.public, self.challenge, self.signature, now=101))
        self.assertEqual(len(self.public.thumbprint), 43)
        self.assertEqual(DevicePublicKey.parse(self.public.jwk), self.public)

    def test_cross_instance_session_action_nonce_and_request_are_rejected(self):
        for values in (dict(instance="https://other.invalid"), dict(operation="commit"),
                dict(session_id="33333333-3333-4333-8333-333333333333"),
                dict(device_id="33333333-3333-4333-8333-333333333333"),
                dict(nonce=encode(b"x" * 32)), dict(request_sha256="b" * 64)):
            with self.assertRaises(ContractError):
                verify_possession(self.public, replace(self.challenge, **values), self.signature, now=101)

    def test_expired_future_and_noncanonical_signatures_are_rejected(self):
        for now in (99, 160, True):
            with self.assertRaises(ContractError):
                verify_possession(self.public, self.challenge, self.signature, now=now)
        for value in (self.signature + "=", encode(b"\0" * 64), "x" * 10000):
            with self.assertRaises(ContractError):
                verify_possession(self.public, self.challenge, value, now=101)

    def test_private_key_members_other_curves_and_off_curve_points_are_rejected(self):
        for value in ({**self.public.jwk, "d": "private"}, {**self.public.jwk, "crv": "P-384"},
                dict(kty="EC", crv="P-256", x=encode(b"\0" * 32), y=encode(b"\0" * 32))):
            with self.assertRaises(ContractError):
                DevicePublicKey.parse(value)

    def test_challenge_lifetime_and_non_origin_are_not_caller_parameters(self):
        for values in (dict(expires_at=221), dict(instance="http://cloudfile.invalid"),
                dict(instance="https://cloudfile.invalid/path"), dict(operation="upload-anything")):
            with self.assertRaises(ContractError):
                verify_possession(self.public, replace(self.challenge, **values), self.signature, now=101)
