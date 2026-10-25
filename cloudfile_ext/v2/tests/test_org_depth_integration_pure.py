"""Trusted Directory + Org depth contract integration (pure, no CE writes)."""
from datetime import datetime, timedelta, timezone
import unittest

from cloudfile_ext.v2.errors import IdentityUnavailable
from cloudfile_ext.v2.org_depth import trusted_scoped_memberships


def when(offset=0):
    return (datetime.now(timezone.utc) + timedelta(seconds=offset)).isoformat()


def org(name, parent=None, namespace='directory'):
    return {'subject_type': 'org', 'namespace': namespace,
            'external_id': name, 'parent_external_id': parent, 'name': name}


def context(*, uid='user-9', status='active', parent_hint=True):
    return {'userId': uid, 'status': status, 'generated_at': when(), 'etag': 'r1',
            'attributes': {'employee_no': 'E-9'},
            'organizations': [{'namespace': 'directory', 'external_id': 'leaf'}],
            'roles': [{'namespace': 'role', 'external_id': 'reviewer'}],
            'organization_ancestors': (
                [{'namespace': 'directory', 'external_id': 'middle'},
                 {'namespace': 'directory', 'external_id': 'root'}]
                if parent_hint else [])}


def catalog(*, groups=None, offset=0):
    if groups is None:
        groups = [org('root'), org('middle', 'root'), org('leaf', 'middle'),
                  {'subject_type': 'role', 'namespace': 'role',
                   'external_id': 'reviewer', 'name': 'Reviewer'}]
    return {'contract_version': '2.0', 'view': 'entities',
            'generated_at': when(offset), 'groups': groups}


class TrustedDepthIntegrationTests(unittest.TestCase):
    def chosen(self, level, **kwargs):
        return trusted_scoped_memberships(
            context(), catalog(), 'user-9', org_level=level,
            expected_namespaces={('org', 'directory'), ('role', 'role')}, **kwargs)

    def test_etech_default_direct_only_and_parent_depths(self):
        direct = self.chosen(1)
        self.assertEqual(direct, frozenset({
            ('org', 'directory', 'leaf'), ('role', 'role', 'reviewer')}))
        self.assertEqual(self.chosen(2) - direct,
                         {('org', 'directory', 'middle')})
        self.assertEqual(self.chosen(0) - direct,
                         {('org', 'directory', 'middle'),
                          ('org', 'directory', 'root')})

    def test_generic_provider_works_with_its_own_namespace(self):
        items = [org('root', namespace='corp'), org('leaf', 'root', 'corp'),
                 {'subject_type': 'role', 'namespace': 'business',
                  'external_id': 'auditor', 'name': 'Auditor'}]
        user = context(parent_hint=False)
        user['organizations'] = [{'namespace': 'corp', 'external_id': 'leaf'}]
        user['roles'] = [{'namespace': 'business', 'external_id': 'auditor'}]
        result = trusted_scoped_memberships(user, catalog(groups=items),
                                            'user-9', org_level=0)
        self.assertEqual(result, frozenset({
            ('org', 'corp', 'root'), ('org', 'corp', 'leaf'),
            ('role', 'business', 'auditor')}))

    def test_broken_catalog_cannot_enlarge_or_silently_downgrade(self):
        for groups in (
                [org('root'), org('leaf', 'missing')],
                [org('root'), org('middle', 'root')],  # direct leaf missing
                [org('root'), org('middle', 'root'), org('leaf', 'middle')],
                [org('root'), org('middle', 'root'), org('leaf', 'root'),
                 {'subject_type': 'role', 'namespace': 'role',
                  'external_id': 'reviewer', 'name': 'Reviewer'}]):
            with self.subTest(groups=groups), self.assertRaises(IdentityUnavailable):
                trusted_scoped_memberships(context(), catalog(groups=groups),
                                           'user-9', org_level=0)

    def test_stale_and_disabled_subjects_are_rejected(self):
        with self.assertRaises(IdentityUnavailable):
            trusted_scoped_memberships(context(), catalog(offset=-600),
                                       'user-9', org_level=1)
        with self.assertRaises(IdentityUnavailable):
            trusted_scoped_memberships(context(status='disabled'), catalog(),
                                       'user-9', org_level=1)
        with self.assertRaises(IdentityUnavailable):
            trusted_scoped_memberships(context(), catalog(), 'someone-else',
                                       org_level=1)


if __name__ == '__main__':
    unittest.main()
