from unittest import TestCase
from unittest.mock import patch

import requests
from django.test import override_settings

from cloudfile_ext.v2.writer_runtime import writer_runtime


@override_settings(JWT_PRIVATE_KEY='isolated-writer-unit-test-signing-key')
class WriterRuntimeTests(TestCase):
    def probe(self, root, data, *, cluster=False):
        with patch('cloudfile_ext.v2.writer_runtime.get_inner_fileserver_root', return_value=root), \
             patch('cloudfile_ext.v2.writer_runtime.CLUSTER_MODE', cluster), \
             patch('cloudfile_ext.v2.writer_runtime.requests.get') as get:
            response = get.return_value.__enter__.return_value
            response.status_code = 200
            response.json.return_value = data
            result = writer_runtime()
            self.assertEqual(get.call_args.args, (root.rstrip('/') + '/internal/cf-writer-capabilities/v1',))
            return result

    def test_single_node_reuses_the_existing_address_and_port(self):
        result = self.probe('http://127.0.0.1:18082/', {'checkout': True, 'protection': False})
        self.assertEqual(result, {'checkout': 'ready', 'protection': 'unavailable'})

    def test_one_positive_reply_cannot_attest_a_cluster_or_remote_route(self):
        for root, cluster in [('http://127.0.0.1:8082', True), ('https://files.internal', False)]:
            with self.subTest(root=root):
                result = self.probe(root, {'checkout': True, 'protection': False}, cluster=cluster)
                self.assertEqual(result, {'checkout': 'unknown', 'protection': 'unavailable'})

    def test_unreachable_writer_is_unknown(self):
        with patch('cloudfile_ext.v2.writer_runtime.requests.get', side_effect=requests.Timeout):
            self.assertEqual(writer_runtime(), {'checkout': 'unknown', 'protection': 'unknown'})
