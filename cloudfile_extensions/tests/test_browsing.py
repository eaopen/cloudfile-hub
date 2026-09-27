"""List response filtering; real session/C policy evidence uses the Web fixture."""
import unittest
from cloudfile_extensions.authorization.browsing import filter_entries
from cloudfile_extensions.common.errors import ContractError


class BrowsingTests(unittest.TestCase):
    def test_hide_denied_and_never_upgrade_ce_permission(self):
        class Authority:
            def consume(self, reference, reader):
                if reference == 'hidden':
                    raise ContractError('ACCESS_DENIED', 'Denied', 403)
                self.effective_access = {'write': reference == 'writer'}
                return reader(None, reference)
        entries = [dict(name='hidden', permission='rw'), dict(name='reader', permission='rw'),
                   dict(name='writer', permission='r')]
        result = filter_entries(Authority(), entries, lambda item: item['name'])
        self.assertEqual(result, [dict(name='reader', permission='r'), dict(name='writer', permission='r')])
        self.assertEqual(entries[1]['permission'], 'rw')

    def test_policy_failure_does_not_return_partial_list(self):
        class Authority:
            def consume(self, reference, reader):
                if reference == 'failed':
                    raise ContractError('POLICY_UNAVAILABLE', 'Unavailable', 503)
                self.effective_access = {'write': True}
                return reader(None, reference)
        with self.assertRaises(ContractError) as caught:
            filter_entries(Authority(), [{'name': 'ok'}, {'name': 'failed'}], lambda item: item['name'])
        self.assertEqual(caught.exception.status, 503)
