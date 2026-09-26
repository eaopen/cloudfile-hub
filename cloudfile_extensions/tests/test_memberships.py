from datetime import datetime, timezone
import unittest

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.directory.memberships import plan_memberships


class MembershipTest(unittest.TestCase):
    def setUp(self):
        self.subject = {"userId": "u1", "status": "active", "attributes": {},
                        "organizations": [{"namespace": "dept", "external_id": "d1", "is_primary": True}],
                        "roles": [{"namespace": "role", "external_id": "r1"}], "etag": "one",
                        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
        self.maps = [self.mapping("dept", "dept", "d1", 1),
                     self.mapping("group", "role", "r1", 2),
                     self.mapping("group", "role", "old", 3),
                     {**self.mapping("group", "role", "r1", 4), "provider": "other"}]

    @staticmethod
    def mapping(kind, namespace, external_id, group_id):
        return dict(provider="directory", subject_type=kind, namespace=namespace,
                    external_id=external_id, group_id=group_id)

    def plan(self, current=(1, 3, 4, 99)):
        return plan_memberships(self.subject, user_id="u1", provider_id="directory",
                                mappings=self.maps, current_groups=current, attribute_allowlist=())

    def test_add_remove_and_preserve_manual_and_other_provider_memberships(self):
        plan = self.plan()
        self.assertEqual((plan.add, plan.remove, plan.retain, plan.unmanaged), ((2,), (3,), (1,), (4, 99)))

    def test_disabled_removes_only_owned_memberships(self):
        self.subject["status"] = "disabled"
        self.assertEqual(self.plan().remove, (1, 3))
        self.assertEqual(self.plan().add, ())
        self.assertEqual(self.plan().unmanaged, (4, 99))

    def test_missing_mapping_does_not_silently_drop_source_role(self):
        self.maps = [mapping for mapping in self.maps if mapping["group_id"] != 2]
        with self.assertRaises(ContractError) as caught:
            self.plan()
        self.assertEqual(caught.exception.status, 503)

    def test_colliding_identity_axes_and_cross_provider_ownership_rejected(self):
        for extra in (dict(self.maps[0]), {**self.maps[3], "group_id": 1}):
            with self.subTest(extra=extra):
                original = list(self.maps)
                self.maps.append(extra)
                with self.assertRaises(ContractError) as caught:
                    self.plan()
                self.assertEqual(caught.exception.status, 409)
                self.maps = original

    def test_cold_start_and_idempotent_readback(self):
        self.assertEqual(self.plan(()).add, (1, 2))
        plan = self.plan((1, 2, 4, 99))
        self.assertEqual((plan.add, plan.remove), ((), ()))

    def test_namespace_and_case_are_exact_not_display_names(self):
        self.subject["roles"][0]["namespace"] = "Role"
        with self.assertRaises(ContractError):
            self.plan()

    def test_malformed_native_groups_and_wrong_subject_rejected(self):
        for current in ((True,), (0,), (-1,), (2147483648,), (1, 1)):
            with self.subTest(current=current), self.assertRaises(ContractError):
                self.plan(current)
        self.subject["userId"] = "other"
        with self.assertRaises(ContractError):
            self.plan()
