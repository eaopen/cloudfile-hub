"""Pure enterprise Directory contract tests; no Django/DB/network."""
from datetime import datetime, timedelta, timezone
import unittest

from cloudfile_ext.v2.errors import IdentityUnavailable
from cloudfile_ext.v2.provider_contract import (verified_user, direct_memberships,
                                                validated_entities)


def stamp(delta=0):
    return (datetime.now(timezone.utc) + timedelta(seconds=delta)).isoformat()


def subject(uid='A-38', *, account='engineer', status='active',
            organizations=None, roles=None, ancestors=None):
    return {
        'userId': uid, 'status': status, 'generated_at': stamp(), 'etag': 'rev-1',
        'attributes': {'account': account, 'employee_no': account,
                       'login_name': account},
        'organizations': [] if organizations is None else organizations,
        'organization_ancestors': [] if ancestors is None else ancestors,
        'roles': [] if roles is None else roles,
    }


def catalog(groups=None, *, seconds=0):
    return {'contract_version': '2.0', 'view': 'entities',
            'generated_at': stamp(seconds),
            'groups': [] if groups is None else groups}


class GenericDirectoryUserTests(unittest.TestCase):
    def test_uid_is_authority_account_is_only_creation_metadata(self):
        user = subject(uid='stable-uid-7', account='employee-Z')
        self.assertEqual(verified_user(user, 'stable-uid-7'),
                         ('employee-Z', 'employee-Z'))
        self.assertEqual(verified_user(user, 'stable-uid-7',
                                       account_field='employee_no'),
                         ('employee-Z', 'employee-Z'))
        with self.assertRaises(IdentityUnavailable):
            verified_user(user, 'employee-Z')

    def test_direct_org_role_facts_exclude_ancestors_without_projecting(self):
        value = subject(
            uid='stable-uid-7', organizations=[
                {'namespace': 'directory', 'external_id': 'leaf'}],
            ancestors=[{'namespace': 'directory', 'external_id': 'parent'}],
            roles=[{'namespace': 'role', 'external_id': 'reviewer'}])
        self.assertEqual(direct_memberships(value, 'stable-uid-7'), frozenset({
            ('org', 'directory', 'leaf'), ('role', 'role', 'reviewer')}))
        # No ancestor group permission is inferred here; runtime projection
        # remains a separate reviewed change in Hub #63.

    def test_missing_account_does_not_invent_uid_or_name(self):
        user = subject(uid='stable-uid-7')
        user['attributes'] = {}
        self.assertEqual(verified_user(user, 'stable-uid-7'), (None, None))
        # NativeIdentity.prepare() remains responsible for preventing any
        # new account creation without valid trusted naming metadata.

    def test_disabled_stale_duplicate_membership_and_bad_account_rejected(self):
        cases = [subject(status='disabled'), subject(uid='other'),
                 subject(organizations=[
                     {'namespace': 'hr', 'external_id': '1'},
                     {'namespace': 'hr', 'external_id': '1'}]),
                 subject(account=123)]
        stale = subject()
        stale['generated_at'] = stamp(-600)
        cases.append(stale)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(IdentityUnavailable):
                verified_user(value, 'A-38')


class GenericDirectoryEntityTests(unittest.TestCase):
    def test_generic_namespace_and_etech_compatibility(self):
        entries = [
            {'subject_type': 'org', 'namespace': 'hr', 'external_id': 'dept-1',
             'name': 'Engineering', 'parent_external_id': 'dept-0'},
            {'subject_type': 'role', 'namespace': 'jobs', 'external_id': 'r-1',
             'name': 'Reviewer'},
        ]
        self.assertEqual(validated_entities(catalog(entries)), {
            ('org', 'hr', 'dept-1'): 'Engineering',
            ('role', 'jobs', 'r-1'): 'Reviewer'})
        with self.assertRaises(IdentityUnavailable):
            validated_entities(catalog(entries), expected_namespaces={
                ('org', 'directory'), ('role', 'role')})
        legacy = [{'subject_type': 'org', 'namespace': 'directory',
                   'external_id': '99', 'name': 'IT'},
                  {'subject_type': 'role', 'namespace': 'role',
                   'external_id': '2', 'name': 'Approver'}]
        self.assertEqual(len(validated_entities(
            catalog(legacy), expected_namespaces={
                ('org', 'directory'), ('role', 'role')})), 2)

    def test_duplicate_invalid_parent_kind_and_stale_snapshot_fail_closed(self):
        good = {'subject_type': 'org', 'namespace': 'hr',
                'external_id': 'child', 'name': 'Child'}
        invalid_cases = [
            catalog([good, good]),
            catalog([dict(good, subject_type='group')]),
            catalog([dict(good, parent_external_id='child')]),
            catalog([dict(good, parent_external_id=42)]),
            catalog([{'subject_type': 'role', 'namespace': 'hr',
                      'external_id': 'r', 'name': 'R', 'parent_external_id': 'x'}]),
            catalog([dict(good, name='')]),
            catalog([good], seconds=-600),
            catalog([good], seconds=600),
            dict(catalog([good]), complete=True, contract_version='bad'),
        ]
        for value in invalid_cases:
            with self.subTest(value=value), self.assertRaises(IdentityUnavailable):
                validated_entities(value)

    def test_empty_catalog_is_valid_fact_but_not_a_global_revoke(self):
        # A caller that publishes entities already enforces non-empty when
        # necessary; parsing an empty catalog never removes native groups.
        self.assertEqual(validated_entities(catalog()), {})


if __name__ == '__main__':
    unittest.main()
