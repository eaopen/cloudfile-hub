import unittest

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.directory.organizations import OrganizationNode, effective_organizations


class OrganizationTest(unittest.TestCase):
    def setUp(self):
        self.direct = [dict(namespace="dept", external_id="child", is_primary=True)]
        self.nodes = [OrganizationNode("dept", "child", "dept", "parent", True),
                      OrganizationNode("dept", "parent", "dept", "root", True),
                      OrganizationNode("dept", "root", None, None, True)]

    def test_effective_ancestors_and_primary_flag(self):
        result = effective_organizations(self.direct, self.nodes)
        self.assertEqual([item["external_id"] for item in result], ["child", "parent", "root"])
        self.assertEqual([item["is_primary"] for item in result], [True, False, False])
        self.assertEqual(effective_organizations(self.direct, list(reversed(self.nodes))), result)

    def test_disabled_ancestor_excluded_and_disabled_direct_grants_nothing(self):
        self.nodes[1] = OrganizationNode("dept", "parent", "dept", "root", False)
        self.assertEqual([item["external_id"] for item in effective_organizations(self.direct, self.nodes)], ["child", "root"])
        self.nodes[0] = OrganizationNode("dept", "child", "dept", "parent", False)
        self.assertEqual(effective_organizations(self.direct, self.nodes), [])

    def test_missing_cycle_and_disabled_cycle_reject(self):
        for nodes in (self.nodes[:2],
                      [self.nodes[0], OrganizationNode("dept", "parent", "dept", "child", True)],
                      [OrganizationNode("dept", "child", "dept", "child", False)]):
            with self.subTest(nodes=nodes), self.assertRaises(ContractError) as caught:
                effective_organizations(self.direct, nodes)
            self.assertEqual(caught.exception.status, 503)

    def test_namespaces_are_distinct_and_explicit_parent_can_cross_namespace(self):
        self.nodes.append(OrganizationNode("other", "root", None, None, True))
        self.nodes[1] = OrganizationNode("dept", "parent", "other", "root", True)
        self.assertEqual(effective_organizations(self.direct, self.nodes)[-1]["namespace"], "other")

    def test_multiple_directs_merge_without_creating_multiple_primaries(self):
        self.direct.append(dict(namespace="dept", external_id="parent", is_primary=False))
        self.assertEqual(len(effective_organizations(self.direct, self.nodes)), 3)
        self.direct[-1]["is_primary"] = True
        with self.assertRaises(ContractError):
            effective_organizations(self.direct, self.nodes)

    def test_duplicate_and_malformed_nodes_reject(self):
        for extra in (self.nodes[0], OrganizationNode("dept", "x", None, "root", True),
                      OrganizationNode("dept", "x", None, None, 1)):
            with self.subTest(extra=extra), self.assertRaises(ContractError):
                effective_organizations(self.direct, self.nodes + [extra])

    def test_depth_bound_and_empty_affiliations(self):
        nodes = [OrganizationNode("dept", str(i), "dept" if i else None, str(i-1) if i else None, True) for i in range(129)]
        with self.assertRaises(ContractError):
            effective_organizations([dict(namespace="dept", external_id="128", is_primary=False)], nodes)
        self.assertEqual(effective_organizations([], self.nodes), [])
