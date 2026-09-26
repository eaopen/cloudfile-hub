"""Independent directory manage grants. Never a content permission or CE share."""
from ..common.errors import invalid
from ..directory.protocol import validate_subject
from ..resources.paths import resource_ref, is_descendant_or_equal
from .core import identity
from .rules import ACLRules, rule_value


def admin_value(value):
    if not isinstance(value, dict) or value.get("kind") != "dir" or value.get("permission") != "manage":
        raise invalid("Directory delegation requires manage permission")
    checked = rule_value({**value, "permission": "r"})
    return {**checked, "permission": "manage"}


class DirectoryAdmins(ACLRules):
    TABLE = "cf_dir_admin"
    ACTION_PREFIX = "admin"
    validate = staticmethod(admin_value)

    def scopes(self, reference, *, subject, attribute_allowlist=(), locking=False):
        """Matching stored scopes only; caller must separately prove qualification,
        current generation, no content denial and management operation authority.
        """
        ref = resource_ref(reference)
        subject = validate_subject(subject, requested_user_id=subject.get("userId"),
                                   attribute_allowlist=attribute_allowlist)
        if subject["status"] != "active":
            return []
        principals = {identity("user", self.provider, "user", subject["userId"])}
        principals.update(identity("dept", self.provider, item["namespace"], item["external_id"])
            for item in subject["organizations"] + subject.get("organization_ancestors", []))
        principals.update(identity("group", self.provider, item["namespace"], item["external_id"])
            for item in subject["roles"])
        return [row for row in self.candidates(ref, locking=locking)
            if identity(row["subject"]["type"], row["subject"]["provider"],
                row["subject"]["namespace"], row["subject"]["external_id"]) in principals
            and ((row["path"] == ref["path"] and ref["kind"] == "dir") or
                 (row["inherit"] and is_descendant_or_equal(ref["path"], row["path"])))]

    @staticmethod
    def permits(scopes, reference, *, inherit=False):
        """Scope containment, not a login/access grant. No scope may be amplified.
        Exact-only grant cannot create an inheritable grant, even at same path.
        """
        ref = resource_ref(reference)
        if type(inherit) is not bool:
            raise invalid("Invalid delegation inheritance")
        for row in scopes:
            value = admin_value({key: row[key] for key in ("path", "kind", "subject", "permission", "inherit")})
            if row.get("repo_id") != ref["repo_id"]:
                continue
            if inherit and not value["inherit"]:
                continue
            if ((value["path"] == ref["path"] and ref["kind"] == "dir") or
                (value["inherit"] and is_descendant_or_equal(ref["path"], value["path"]))):
                return True
        return False
