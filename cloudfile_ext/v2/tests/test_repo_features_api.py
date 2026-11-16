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
