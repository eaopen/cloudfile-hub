"""Catalog planning cannot introduce a second population membership writer."""
import pytest

from cloudfile_extensions.directory.catalog import plan_catalog
from cloudfile_extensions.directory.configuration import membership_mode, subject_ttl
from cloudfile_extensions.directory.reconcile import SyncRefused
from cloudfile_extensions.directory.snapshot import validate


def test_catalog_creates_parent_first_without_members_and_retains_retired_mappings():
    entries = validate([
        dict(external_id="child", name="Child", subject_type="dept", parent_external_id="root", member_user_ids=["must-not-add"]),
        dict(external_id="root", name="Root", subject_type="dept", members=["must-not-add"]),
        dict(external_id="role:1", name="Renamed", subject_type="group"),
    ])
    mapped = {"role:1": dict(group_id=3, name="Old", parent_external_id=None),
              "retired": dict(group_id=4, name="Retired", parent_external_id=None)}
    plan = plan_catalog(entries, mapped)
    assert [entry["external_id"] for entry in plan.create] == ["root", "child"]
    assert all(entry["members"] == [] for entry in plan.create)
    assert plan.rename == [dict(group_id=3, name="Renamed")]
    assert not plan.add and not plan.remove and not plan.unmap
    assert plan_catalog([], mapped).empty


def test_catalog_never_silently_reparents_native_groups():
    entries = validate([dict(external_id="dept", name="Dept", subject_type="dept")])
    with pytest.raises(SyncRefused):
        plan_catalog(entries, {"dept": dict(group_id=1, name="Dept", parent_external_id="old")})


def test_membership_mode_and_ttl_are_explicit_bounded_deployment_values():
    assert membership_mode(None) == "snapshot"
    assert membership_mode(dict(membership_mode="subject_ttl")) == "subject_ttl"
    assert subject_ttl({}) == 1800
    for ttl in (True, "1800", 59, 1801, None):
        with pytest.raises(ValueError):
            subject_ttl(dict(subject_ttl=ttl))
    with pytest.raises(ValueError):
        membership_mode(dict(membership_mode="both"))
