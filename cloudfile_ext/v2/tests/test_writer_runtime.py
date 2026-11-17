from unittest import TestCase
from unittest.mock import patch

from django.test import override_settings

from cloudfile_ext.v2.writer_runtime import writer_runtime


class WriterRuntimeTests(TestCase):
    @override_settings(CLOUDFILE_WRITER_ROOTS=[])
    def test_missing_inventory_is_unknown(self):
        self.assertEqual(writer_runtime(), dict(checkout='unknown', protection='unknown'))

    @override_settings(CLOUDFILE_WRITER_ROOTS=['http://first', 'http://second'],
                       JWT_PRIVATE_KEY='isolated-writer-unit-test-signing-key')
    def test_all_direct_writers_must_confirm_each_capability(self):
        def probe(root, token):
            self.assertTrue(token)
            return dict(checkout='ready', protection='unknown' if root.endswith('second') else 'unavailable')
        with patch('cloudfile_ext.v2.writer_runtime._probe', side_effect=probe):
            self.assertEqual(writer_runtime(), dict(checkout='ready', protection='unavailable'))
