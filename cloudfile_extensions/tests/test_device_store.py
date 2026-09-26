"""Isolated real SQL persistence/proof cases; no browser/file authorization claim."""
import base64
from uuid import uuid4

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.local_edit.device_proof import DevicePublicKey
from cloudfile_extensions.local_edit.device_store import DeviceStore
from cloudfile_extensions.schema.runner import SchemaRunner
from cloudfile_extensions.tests.test_schema import DatabaseTestCase


def encode(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


class DeviceStoreTests(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        SchemaRunner(self.connection).apply()
        self.store = DeviceStore()
        self.private = ec.generate_private_key(ec.SECP256R1())
        numbers = self.private.public_key().public_numbers()
        self.public = DevicePublicKey.parse(dict(kty="EC", crv="P-256",
            x=encode(numbers.x.to_bytes(32, "big")), y=encode(numbers.y.to_bytes(32, "big"))))
        self.device_id, self.session_id = str(uuid4()), str(uuid4())
        self.owner = dict(provider="etech", actor="user-1", device_id=self.device_id)

    def create(self, sql):
        return self.store.create_pending(sql, **self.owner, public_key=self.public)

    def issue(self, sql, operation="pair"):
        return self.store.issue(sql, **self.owner, instance="https://cloudfile.invalid",
            session_id=self.session_id, operation=operation, request_sha256="a" * 64)

    def sign(self, challenge):
        r, s = decode_dss_signature(self.private.sign(challenge.message(), ec.ECDSA(hashes.SHA256())))
        return encode(r.to_bytes(32, "big") + s.to_bytes(32, "big"))

    def consume(self, sql, challenge):
        return self.store.consume(sql, provider="etech", actor="user-1", challenge=challenge, signature=self.sign(challenge))

    def test_actual_pair_and_replay_rejection(self):
        self.connection.begin()
        try:
            with self.connection.cursor() as sql:
                self.create(sql)
                challenge = self.issue(sql)
                self.assertEqual(self.consume(sql, challenge), dict(device_id=self.device_id, state="active", revision="2"))
            self.connection.commit()
            self.connection.begin()
            with self.connection.cursor() as sql:
                with self.assertRaises(ContractError):
                    self.consume(sql, challenge)
        finally:
            self.connection.rollback()

    def test_revoke_invalidates_previously_issued_challenge(self):
        self.connection.begin()
        try:
            with self.connection.cursor() as sql:
                self.create(sql)
                self.consume(sql, self.issue(sql))
                challenge = self.issue(sql, "claim")
                self.assertEqual(self.store.revoke(sql, **self.owner, expected_revision=2)["revision"], "3")
                with self.assertRaises(ContractError):
                    self.consume(sql, challenge)
            self.connection.commit()
        finally:
            self.connection.rollback()

    def test_rollback_does_not_consume_proof_or_activate_device(self):
        self.connection.begin()
        with self.connection.cursor() as sql:
            self.create(sql)
            challenge = self.issue(sql)
        self.connection.commit()
        self.connection.begin()
        with self.connection.cursor() as sql:
            self.consume(sql, challenge)
        self.connection.rollback()
        self.connection.begin()
        try:
            with self.connection.cursor() as sql:
                self.assertEqual(self.consume(sql, challenge)["state"], "active")
            self.connection.commit()
        finally:
            self.connection.rollback()

    def test_other_owner_and_expiry_never_activate_device(self):
        self.connection.begin()
        try:
            with self.connection.cursor() as sql:
                self.create(sql)
                challenge = self.issue(sql)
                with self.assertRaises(ContractError):
                    self.store.issue(sql, **{**self.owner, "actor": "user-2"}, instance="https://cloudfile.invalid",
                        session_id=self.session_id, operation="pair", request_sha256="a" * 64)
                sql.execute("UPDATE cf_local_device_challenge SET expires_at=0")
                with self.assertRaises(ContractError):
                    self.consume(sql, challenge)
                sql.execute("SELECT state FROM cf_local_device WHERE device_id=%s", (self.device_id,))
                self.assertEqual(sql.fetchone()[0], "pending")
        finally:
            self.connection.rollback()
