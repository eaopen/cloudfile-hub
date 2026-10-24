"""Native CE upgrade discovery is additive and does not recreate repositories."""
import unittest
from uuid import uuid4

from cloudfile_ext.v2.native_discovery import classify, native_key, storage_catalog_status


class NativeDiscoveryContractTest(unittest.TestCase):
    def setUp(self):
        self.repo_id = str(uuid4())
        self.marker = native_key(self.repo_id)

    def test_existing_native_repo_is_already_native(self):
        self.assertEqual(classify(self.repo_id, True, None, None, None), 'NATIVE_REGISTERED')
        self.assertEqual(classify(self.repo_id, True, None, self.marker, 'active'), 'NATIVE_REGISTERED')
        self.assertEqual(classify(self.repo_id, True, None, self.marker, 'retired'), 'NATIVE_REGISTERED')

    def test_database_missing_repo_is_not_repaired_by_inserting_record(self):
        self.assertEqual(classify(self.repo_id, False, None, None, None), 'NATIVE_RESOURCE_MISSING')
        self.assertEqual(classify(self.repo_id, False, None, self.marker, 'active'), 'NATIVE_RESOURCE_MISSING')

    def test_broken_mapping_cannot_fallback_to_native(self):
        for route, key, state in (
            (None, self.marker, 'reserved'),
            (None, self.repo_id, 'active'),
            ('auto-local:other', self.repo_id, 'active'),
            ('auto-local:' + self.repo_id, self.marker, 'active'),
        ):
            self.assertIn(classify(self.repo_id, True, route, key, state),
                          ('STORAGE_BINDING_CONFLICT', 'STORAGE_BINDING_INCOMPLETE'))

    def test_new_uuid_and_existing_custom_key_both_route(self):
        self.assertEqual(classify(self.repo_id, True, 'auto-local:' + self.repo_id, None, None),
                         'V2_ROUTED')
        self.assertEqual(classify(self.repo_id, True, 'auto-local:old-key', 'old-key', 'active'),
                         'V2_ROUTED')
        self.assertEqual(storage_catalog_status(self.repo_id, True, None, None,
                         'auto-local:' + self.repo_id, True), 'READY')

    def test_external_storage_must_not_be_claimed(self):
        self.assertEqual(classify(self.repo_id, True, 'external-s3', None, None),
                         'EXTERNAL_STORAGE_REQUIRES_REVIEW')

    def test_native_marker_requires_exact_canonical_uuid(self):
        self.assertIsNone(native_key(self.repo_id.upper()))
        self.assertIsNone(native_key('etech01'))
        self.assertEqual(self.marker, 'native-' + self.repo_id)

    def test_two_way_registry_diagnostic_codes(self):
        rid = self.repo_id
        self.assertEqual(storage_catalog_status(rid, True, None, None, None, True), 'READY')
        self.assertEqual(storage_catalog_status(rid, False, 'native-' + rid, 'active', None, False), 'REPO_MISSING')
        self.assertEqual(storage_catalog_status(rid, True, 'native-' + rid, 'active', None, True), 'READY')
        self.assertEqual(storage_catalog_status(rid, True, rid, 'active', 'auto-local:' + rid, True), 'READY')
        self.assertEqual(storage_catalog_status(rid, True, rid, 'reserved', 'auto-local:' + rid, True), 'RESERVED')
        self.assertEqual(storage_catalog_status(rid, True, rid, 'retired', 'auto-local:' + rid, True), 'RETIRED')
        self.assertEqual(storage_catalog_status(rid, True, rid, 'active', 'auto-local:broken', True), 'BINDING_ERROR')
        self.assertEqual(storage_catalog_status(rid, True, 'native-' + rid, 'active', None, False), 'RESOURCE_UNREADABLE')
        self.assertEqual(storage_catalog_status(rid, False, 'native-' + rid, 'active', None, False,
                                               in_trash=True), 'IN_TRASH')
        self.assertEqual(storage_catalog_status(rid, False, 'native-' + rid, 'active', None, False,
                                               in_gc=True), 'GC_PENDING')
        self.assertEqual(storage_catalog_status(rid, True, None, None, None, True,
                                               virtual=True), 'VIRTUAL_REPO')
