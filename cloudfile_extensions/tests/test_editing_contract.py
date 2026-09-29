"""Unsupported transports and client-supplied identities fail before authority."""
import unittest
from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.editing.service import EditingService


class EditingContractTest(unittest.TestCase):
    def test_unimplemented_modes_and_automatic_paths_are_not_commands(self):
        service = object.__new__(EditingService)
        for operation in ('editor-session', 'checkout-set', 'auto-upload', 'third-party-checkin'):
            with self.subTest(operation=operation), self.assertRaises(ContractError) as caught:
                service.command(operation, {}, idempotency_key='attempt')
            self.assertEqual(caught.exception.status, 503)

    def test_caller_cannot_supply_owner_holder_or_policy(self):
        service = object.__new__(EditingService)
        request = dict(reference={}, base_file_id='b' * 40, token='a' * 64)
        for field in ('actor', 'owner', 'username', 'native_user', 'native_username', 'holder', 'hard_seconds', 'management', 'publisher'):
            with self.subTest(field=field), self.assertRaises(ContractError) as caught:
                service.command('checkout', {**request, field: 'untrusted'}, idempotency_key='attempt')
            self.assertEqual(caught.exception.status, 400)
