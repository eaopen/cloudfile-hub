"""Native CE upgrade discovery is additive and does not recreate repositories."""
import unittest
from uuid import uuid4

from cloudfile_ext.v2.native_discovery import classify, native_key


class NativeDiscoveryContractTest(unittest.TestCase):
    def setUp(self):
        self.repo_id = str(uuid4())
        self.marker = native_key(self.repo_id)

    def test_existing_native_repo_needs_registration(self):
        self.assertEqual(classify(self.repo_id, True, None, None, None), 'NATIVE_UNREGISTERED')
        self.assertEqual(classify(self.repo_id, True, None, self.marker, 'active'), 'NATIVE_REGISTERED')
        self.assertEqual(classify(self.repo_id, True, None, self.marker, 'retired'), 'NATIVE_REGISTERED')

    def test_database_missing_repo_is_not_repaired_by_inserting_record(self):
        self.assertEqual(classify(self.repo_id, False, None, None, None), 'NATIVE_RESOURCE_MISSING')
        self.assertEqual(classify(self.repo_id, False, None, self.marker, 'active'), 'NATIVE_RESOURCE_MISSING')

    def test_broken_mapping_cannot_fallback_to_native(self):
        for route, key, state in (
            (None, self.marker, 'reserved'),
            (None, self.repo_id, 'active'),
            ('auto-local:' + self.repo_id, None, None),
            ('auto-local:other', self.repo_id, 'active'),
            ('auto-local:' + self.repo_id, self.marker, 'active'),
        ):
            self.assertIn(classify(self.repo_id, True, route, key, state),
                          ('STORAGE_BINDING_CONFLICT', 'STORAGE_BINDING_INCOMPLETE'))

    def test_external_storage_must_not_be_claimed(self):
        self.assertEqual(classify(self.repo_id, True, 'external-s3', None, None),
                         'EXTERNAL_STORAGE_REQUIRES_REVIEW')

    def test_native_marker_requires_exact_canonical_uuid(self):
        self.assertIsNone(native_key(self.repo_id.upper()))
        self.assertIsNone(native_key('etech01'))
        self.assertEqual(self.marker, 'native-' + self.repo_id)
