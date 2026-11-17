from unittest import TestCase
from unittest.mock import Mock, patch

from cloudfile_ext.v2.http import RepoFeatures, StorageReconcile


class RepoCapabilityContractTests(TestCase):
    def test_targeted_inventory_never_scans_global_storage(self):
        req = Mock(data={'repo_ids': []})
        with patch('cloudfile_ext.v2.native_discovery.reconcile_from_hub') as scan, \
             patch('cloudfile_ext.v2.native_discovery.inspect_from_hub', return_value={}) as lookup:
            self.assertEqual(StorageReconcile().post(req).data, {'registered': 0, 'statuses': {}})
            lookup.assert_called_once_with([], with_features=True)
            scan.assert_not_called()

    def test_invalid_or_unauthorized_changes_are_rejected_before_sql(self):
        req = Mock(data={'protection': 'false'})
        req.user.admin_permissions.can_manage_library.return_value = False
        self.assertEqual(RepoFeatures().post(req, 'ignored').status_code, 403)
        req.user.admin_permissions.can_manage_library.return_value = True
        for invalid in ({'protection': 'false'}, {'other': True}, {}, []):
            req.data = invalid
            self.assertEqual(RepoFeatures().post(req, 'ignored').status_code, 400)

    def test_read_configuration_independently_of_runtime(self):
        from unittest.mock import MagicMock
        conn = MagicMock()
        cursor = conn.cursor.return_value.__enter__.return_value
        with patch('django.db.connection', conn), patch('seahub.utils.db_api.SeafileDB') as db, \
             patch('cloudfile_ext.v2.writer_runtime.writer_runtime',
                   return_value=dict(checkout='ready', protection='unknown')):
            db.return_value.db_name = 'seafile_db'
            req = Mock()
            for rows, expected in (([], 404), ([(None,)], 200), ([('protection',)], 200)):
                cursor.fetchall.return_value = rows
                response = RepoFeatures().get(req, 'repo-id')
                self.assertEqual(response.status_code, expected)
                if expected == 200:
                    self.assertEqual(response.data['capabilities']['protection'],
                                     dict(configured=rows == [('protection',)], runtime='unknown'))
                    self.assertEqual(response['Cache-Control'], 'no-store')
