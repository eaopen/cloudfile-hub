"""Entity-only planning leaves GroupUser exclusively to subject preparation."""
from . import reconcile, snapshot


def plan_catalog(entries, mapped):
    # Keep retired ownership mappings. Otherwise stale GroupUser rows become
    # unmanaged and the next per-user projection can no longer revoke them.
    plan = reconcile.Plan()
    for entry in snapshot.dept_order(entries):
        existing = mapped.get(entry["external_id"])
        if existing is None:
            plan.create.append({**entry, "members": []})
        elif existing["parent_external_id"] != entry["parent_external_id"]:
            raise reconcile.SyncRefused("department reparenting requires explicit migration")
        elif existing["name"] != entry["name"]:
            plan.rename.append(dict(group_id=existing["group_id"], name=entry["name"]))
    return plan
