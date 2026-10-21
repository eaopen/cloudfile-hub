"""Isolated V2 policy proofs; these tests do not claim that fileserver is guarded."""
import unittest
from cloudfile_ext.v2.acl_policy import (Decision, PolicyError, Principal, Rule, narrow_to_native,
                                         resolve)

REPO = '00000000-0000-4000-8000-000000000001'
U = Principal('etech', 'uid-a', frozenset({('org','dept','42'), ('role','role','writer')}))

def rule(path, subject_type, external_id, permission, *, inherit=True, share=False, namespace=None):
    return Rule(REPO, path, 'etech', subject_type,
                namespace or ('user' if subject_type == 'user' else 'dept' if subject_type == 'org' else 'role'),
                external_id, permission, inherit, share)


def permission(path, rows, native='rw', principal=U, **kwargs):
    return resolve(REPO, path, principal, native, rows, **kwargs)


class HierarchicalDirectoryTests(unittest.TestCase):
    def test_default_inherits_and_deeper_user_rule_overrides(self):
        rows = [rule('/A', 'user', 'uid-a', 'rw'), rule('/A/B', 'user', 'uid-a', 'r')]
        self.assertEqual(permission('/A/X', rows).permission, 'rw')
        self.assertEqual(permission('/A/B/doc', rows).permission, 'r')
        self.assertEqual(permission('/A/C', rows).permission, 'rw')

    def test_non_inheriting_rule_only_applies_on_exact_directory(self):
        rows = [rule('/A', 'user', 'uid-a', 'r', inherit=False)]
        self.assertEqual(permission('/A', rows).permission, 'r')
        self.assertEqual(permission('/A/B', rows).permission, 'rw')

    def test_parent_user_rule_beats_deeper_group_rule_like_pro(self):
        rows = [rule('/A', 'user', 'uid-a', 'r'), rule('/A/B', 'role', 'writer', 'rw')]
        self.assertEqual(permission('/A/B', rows).permission, 'r')

    def test_user_exception_beats_group_invisible_at_same_path(self):
        rows = [rule('/A', 'org', '42', 'invisible'), rule('/A', 'user', 'uid-a', 'rw')]
        self.assertEqual(permission('/A', rows).permission, 'rw')

    def test_same_group_tier_deny_beats_grant(self):
        rows = [rule('/A', 'org', '42', 'r'),
                rule('/A', 'org', '99', 'invisible')]
        extra = Principal('etech', 'uid-a', frozenset({('org','dept','42'),('org','dept','99')}))
        self.assertEqual(permission('/A', rows, principal=extra).permission, 'invisible')

    def test_same_level_positive_groups_merge_to_readwrite(self):
        rows = [rule('/A', 'org', '42', 'r'), rule('/A', 'org', '99', 'rw')]
        user = Principal('etech', 'uid-a', frozenset({('org', 'dept', '42'), ('org', 'dept', '99')}))
        self.assertEqual(permission('/A', rows, principal=user).permission, 'rw')
        self.assertEqual(permission('/A/child', rows, principal=user).permission, 'rw')

    def test_deny_has_priority_even_if_other_group_grants_write(self):
        rows = [rule('/A', 'org', '42', 'invisible'), rule('/A', 'org', '99', 'rw')]
        user = Principal('etech', 'uid-a', frozenset({('org', 'dept', '42'), ('org', 'dept', '99')}))
        self.assertFalse(permission('/A', rows, principal=user).can_read)

    def test_deeper_group_grant_cannot_bypass_invisible_ancestor(self):
        rows = [rule('/A', 'org', '42', 'invisible'), rule('/A/B', 'org', '42', 'rw')]
        self.assertEqual(permission('/A/B', rows).permission, 'invisible')  # Cannot traverse denied parent
        self.assertEqual(permission('/A', rows).permission, 'invisible')

    def test_org_priority_precedes_role_track(self):
        rows = [rule('/A', 'org', '42', 'r'),rule('/A/B','role','writer','rw')]
        self.assertEqual(permission('/A/B',rows).permission,'r')

    def test_deny_blocks_contents_and_invisible_hides(self):
        for denied in ('invisible',):
            decision = permission('/A', [rule('/A','user','uid-a',denied)])
            self.assertFalse(decision.can_read)
            self.assertFalse(decision.can_write)
            self.assertFalse(decision.visible)

    def test_denied_parent_cannot_be_bypassed_by_deeper_grant(self):
        rows = [rule('/A', 'user', 'uid-a', 'invisible'),rule('/A/B','user','uid-a','rw')]
        self.assertEqual(permission('/A/B',rows).permission,'invisible')

    def test_lower_layer_readonly_is_not_promoted_to_write(self):
        rows = [rule('/A','user','uid-a','rw')]
        self.assertEqual(permission('/A',rows,native='r').permission,'rw')  # Pro override of share r
        self.assertEqual(permission('/A',rows,hard_readonly=True).permission,'r')

    def test_removing_rule_falls_back_to_native(self):
        self.assertEqual(permission('/A',[]).permission,'rw')
        self.assertEqual(permission('/A',[rule('/A','user','uid-a','invisible')]).permission,'invisible')

    def test_provider_and_duplicates_fail_closed(self):
        with self.assertRaises(PolicyError):
            permission('/A',[rule('/A','user','uid-a','r')]*2)
        with self.assertRaises(PolicyError):
            permission('/A',[Rule(REPO,'/A','other','user','user','uid-a','rw')])

    def test_noncanonical_or_malformed_acl_denied(self):
        for path in ('A','/A/','/A/../B','/A//B','/A\\B'):
            with self.assertRaises(PolicyError):
                permission(path, [])
        with self.assertRaises(PolicyError):
            rule('/A','user','uid-a','invisible',share=True)
        with self.assertRaises(PolicyError):
            rule('/A','user','uid-a','none')  # Removed configuration choice.


class SharedRootTests(unittest.TestCase):
    def test_no_library_permission_needs_positive_sharing_root(self):
        rows=[rule('/Projects','org','42','rw',share=True)]
        self.assertEqual(permission('/Projects',rows,native=None).permission,'rw')
        self.assertEqual(permission('/Projects/Sub',rows,native=None).permission,'rw')
        self.assertFalse(permission('/',rows,native=None).can_read)
        self.assertFalse(permission('/Other',rows,native=None).can_read)

    def test_share_mode_false_and_denies_never_create_access(self):
        self.assertFalse(permission('/Projects',[rule('/Projects','org','42','rw')],native=None).can_read)
        with self.assertRaises(PolicyError):
            rule('/Projects','user','uid-a','invisible',share=True)

    def test_personal_denial_at_shared_root_overrides_group_grant(self):
        rows=[rule('/Projects','org','42','r',share=True),rule('/Projects','user','uid-a','invisible')]
        self.assertFalse(permission('/Projects',rows,native=None).can_read)

    def test_share_root_without_inheritance_cannot_grant_child(self):
        rows=[rule('/Projects','org','42','rw',share=True,inherit=False)]
        self.assertTrue(permission('/Projects',rows,native=None).can_read)
        self.assertFalse(permission('/Projects/Sub',rows,native=None).can_read)

    def test_unready_subject_fails_closed(self):
        principal=Principal('etech','uid-a',U.groups,ready=False)
        self.assertFalse(permission('/Projects',[rule('/Projects','org','42','rw',share=True)],native=None,principal=principal).can_read)


class NativeNarrowingTests(unittest.TestCase):
    """The native library grant qualifies a V2 decision; a share root is its own grant."""

    def decide(self, path, rows, native='rw'):
        return resolve(REPO, path, U, native, rows)

    def test_native_read_qualifies_a_v2_write(self):
        # 设计口径：库 r 可经有效目录规则提升为 rw；native 是资格，不是上限。
        decision = narrow_to_native(Decision('rw', '/', True), 'r')
        self.assertEqual(decision.permission, 'rw')
        self.assertEqual(narrow_to_native(Decision('rw', '/', True), 'rw').permission, 'rw')
        # 规则自身的降级仍然有效。
        self.assertEqual(narrow_to_native(Decision('r', '/Projects', True), 'rw').permission, 'r')

    def test_share_root_survives_an_absent_native_grant(self):
        # No library membership: CE reports none/None, yet the share root is readable.
        for native in (None, 'none'):
            decision = self.decide('/Projects/Sub', [rule('/Projects', 'org', '42', 'rw', share=True)], native=None)
            self.assertTrue(decision.can_read)
            kept = narrow_to_native(decision, native)
            self.assertIsNotNone(kept, native)
            self.assertEqual(kept.permission, 'rw')
            self.assertEqual(kept.qualified_root, '/Projects')

    def test_absent_native_grant_still_denies_outside_a_share_root(self):
        library = self.decide('/writable', [rule('/writable', 'user', 'uid-a', 'rw')], native='rw')
        for native in (None, 'none'):
            self.assertIsNone(narrow_to_native(library, native))
        # A library-root decision is not a share root even when it comes from a rule.
        self.assertIsNone(narrow_to_native(Decision('rw', '/', True), None))

    def test_explicit_native_denial_is_never_overridden(self):
        share = self.decide('/Projects', [rule('/Projects', 'org', '42', 'rw', share=True)], native=None)
        self.assertIsNone(narrow_to_native(share, 'invisible'))


if __name__ == '__main__':
    unittest.main()
