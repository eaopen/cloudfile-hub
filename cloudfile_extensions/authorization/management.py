"""Library management of directory content rules; recovery is not implicit.

Already authenticated actor, current subject and all effect rows share authority.
No public route, administrator bypass, other-connection permission RPC or UI.
"""
from ..common.errors import ContractError
from ..directory.preparation import SubjectPreparation
from ..directory.project import qualified
from .core import PolicyCore
from .rules import ACLRules
from .qualification import NativeLibraryQualification


class LibraryOwnerManagement:
    def __init__(self, preparation, core, *, request_id):
        if not isinstance(preparation, SubjectPreparation) or not isinstance(core, PolicyCore):
            raise ValueError("real subject preparation and native policy core required")
        self.preparation, self.core = preparation, core
        self.state = preparation.state
        self.actor = preparation.actor
        self.epoch = None
        self.current_subject = None
        self.is_owner = False
        self.is_library_admin = False
        self.is_global_library_admin = False
        self.hard_readonly = False
        self.rules = ACLRules(self.state.connection, provider=self.state.provider,
            actor=self.actor, request_id=request_id, authorize=self.authorize,
            finalize=self.finalize, authorize_change=self.authorize_change)


    def authorize(self, cursor, actor, reference):
        permission = self.prepare_authorization(cursor, actor, reference)
        if permission is None or not self.scope_allowed(reference):
            return False
        decision = self.core.evaluate(reference, provider=self.state.provider,
            subject=self.current_subject, rules=self.rules.candidates(reference, locking=True),
            ce_permission=permission, attribute_allowlist=self.preparation.contexts.allowlist,
            hard_readonly=self.hard_readonly)
        # Single-target callers retain their scope and final policy decision.
        return self.decision_allowed(decision)

    def prepare_authorization(self, cursor, actor, reference):
        """Load locked identity/library inputs, never authorize a target path.

        Separating qualification avoids evaluating a group's first object twice.
        Only the exact content-read authority shares these inputs across targets;
        management/write callers still use authorize and their object scope.
        """
        self.epoch = None
        self.current_subject = None
        self.hard_readonly = False
        self.is_owner = False
        self.is_library_admin = False
        self.is_global_library_admin = False
        if actor != self.actor:
            return None
        current = self.preparation.contexts.current(actor)
        if current is None:
            raise ContractError("SUBJECT_UNAVAILABLE", "Current subject must be prepared", 503)
        self.epoch = current["context_epoch"]
        self.current_subject = current["subject"]
        username = self.state.username(actor)
        cursor.execute("SELECT email,is_active,is_staff FROM " + self.state.accounts + " WHERE email=%s FOR UPDATE", (username,))
        accounts = cursor.fetchall()
        if (len(accounts) != 1 or len(accounts[0]) != 3 or
                accounts[0][0] != username or accounts[0][1] != 1 or accounts[0][2] not in (0, 1)):
            return None
        cursor.execute("SELECT user,login_id FROM " + self.state.profiles + " WHERE user=%s OR login_id=%s FOR UPDATE", (username, actor))
        if cursor.fetchall() != ((username, actor),):
            return None
        for schema, table in ((self.state.native_schema, "EmailUser"),
                              (self.state.identity_schema, "profile_profile")):
            cursor.execute("SELECT ENGINE FROM information_schema.tables WHERE table_schema=%s AND table_name=%s", (schema, table))
            if cursor.fetchall() != (("InnoDB",),):
                raise ContractError("POLICY_UNAVAILABLE", "Management identity is unavailable", 503)
        repo = reference["repo_id"]
        cursor.execute("SELECT repo_id FROM Repo WHERE repo_id=%s FOR UPDATE", (repo,))
        if cursor.fetchall() != ((repo,),):
            return None
        cursor.execute("SELECT status FROM RepoInfo WHERE repo_id=%s FOR UPDATE", (repo,))
        statuses = cursor.fetchall()
        if (len(statuses) != 1 or len(statuses[0]) != 1
                or type(statuses[0][0]) is not int or not self.library_status_allowed(statuses[0][0])):
            return None
        self.hard_readonly = statuses[0][0] == 1
        cursor.execute("SELECT repo_id FROM VirtualRepo WHERE repo_id=%s FOR UPDATE", (repo,))
        if cursor.fetchall():
            return None
        cursor.execute("SELECT owner_id FROM RepoOwner WHERE repo_id=%s FOR UPDATE", (repo,))
        owners = cursor.fetchall()
        if len(owners) != 1 or not isinstance(owners[0][0], str) or not owners[0][0]:
            return None
        owner = owners[0][0]
        self.is_owner = owner == username
        for table in ("Repo", "RepoInfo", "VirtualRepo", "RepoOwner"):
            cursor.execute("SELECT ENGINE FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name=%s", (table,))
            if cursor.fetchall() != (("InnoDB",),):
                raise ContractError("POLICY_UNAVAILABLE", "Management library is unavailable", 503)
        self._barriers(repo)
        if accounts[0][2] == 1 and self.requires_system_admin():
            self.is_global_library_admin = self._global_library_admin(cursor, username)
        permission = self.qualification(cursor, reference, username, owner)
        if permission is None and self.is_global_library_admin and self.system_admin_qualification_override():
            permission = "rw"  # Management-only qualification; content read subclasses disable this.
        if (permission is not None and not self.is_owner and not self.is_global_library_admin
                and self.requires_library_admin()):
            self.is_library_admin = self._library_admin(cursor, repo, username)
        return permission

    def decision_allowed(self, decision):
        return decision["visible"] and decision["read"]

    def _library_admin(self, cursor, repo, username):
        """Read the native management markers in this policy transaction."""
        schema = self.state.identity_schema
        for table in ("share_extrasharepermission", "share_extragroupssharepermission"):
            cursor.execute("SELECT ENGINE FROM information_schema.tables WHERE table_schema=%s AND table_name=%s", (schema, table))
            if cursor.fetchall() != (("InnoDB",),):
                raise ContractError("POLICY_UNAVAILABLE", "Library management storage is unavailable", 503)
        user_grants = qualified(schema, "share_extrasharepermission")
        group_grants = qualified(schema, "share_extragroupssharepermission")
        members = qualified(self.state.native_schema, "GroupUser")
        cursor.execute("SELECT permission FROM " + user_grants + " WHERE repo_id=%s AND share_to=%s FOR UPDATE", (repo, username))
        personal = cursor.fetchall()
        if any(len(row) != 1 or row[0] != "admin" for row in personal):
            raise ContractError("POLICY_UNAVAILABLE", "Invalid library management grant", 503)
        if personal:
            return True
        cursor.execute("SELECT ENGINE FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name=%s", ("RepoGroup",))
        if cursor.fetchall() != (("InnoDB",),):
            raise ContractError("POLICY_UNAVAILABLE", "Native group shares are unavailable", 503)
        cursor.execute("SELECT g.permission FROM " + group_grants + " g JOIN " + members +
                       " m ON m.group_id=g.group_id JOIN RepoGroup s ON s.group_id=g.group_id AND s.repo_id=g.repo_id"
                       " WHERE g.repo_id=%s AND m.user_name=%s AND m.is_staff=1 AND s.permission IN ('r','rw') FOR UPDATE",
                       (repo, username))
        groups = cursor.fetchall()
        if any(len(row) != 1 or row[0] != "admin" for row in groups):
            raise ContractError("POLICY_UNAVAILABLE", "Invalid library management grant", 503)
        return bool(groups)

    def _global_library_admin(self, cursor, username):
        """Resolve the account's administrator role under the same transaction."""
        from seahub.constants import SYSTEM_ADMIN
        from seahub.role_permissions.utils import get_enabled_admin_role_permissions_by_role
        schema = self.state.identity_schema
        cursor.execute("SELECT ENGINE FROM information_schema.tables WHERE table_schema=%s AND table_name=%s",
                       (schema, "role_permissions_adminrole"))
        if cursor.fetchall() != (("InnoDB",),):
            raise ContractError("POLICY_UNAVAILABLE", "Administrator roles are unavailable", 503)
        roles = qualified(schema, "role_permissions_adminrole")
        cursor.execute("SELECT role FROM " + roles + " WHERE email=%s FOR UPDATE", (username,))
        assigned = cursor.fetchall()
        if len(assigned) > 1 or any(len(row) != 1 or not isinstance(row[0], str) for row in assigned):
            raise ContractError("POLICY_UNAVAILABLE", "Administrator role is invalid", 503)
        role = assigned[0][0] if assigned else SYSTEM_ADMIN
        return get_enabled_admin_role_permissions_by_role(role)["can_manage_library"] is True

    def can_manage_library(self):
        return (self.is_owner or getattr(self, "is_library_admin", False) or
                getattr(self, "is_global_library_admin", False))

    def requires_library_admin(self):
        return True

    def requires_system_admin(self):
        return True

    def system_admin_qualification_override(self):
        return True

    def library_status_allowed(self, status):
        # Management and mutations retain the native normal-state gate.
        return status == 0

    def qualification(self, cursor, reference, username, owner):
        return "rw" if self.is_owner else None

    def scope_allowed(self, reference):
        return self.is_owner

    def authorize_change(self, cursor, actor, reference, previous, value):
        return actor == self.actor and self.is_owner

    def _barriers(self, repo):
        if (self.state.barrier_active(self.state.provider, self.actor) or
                self.state.jobs.active_barrier(dict(type="repo", provider="cloudfile", external_id=repo))):
            raise ContractError("SUBJECT_UNAVAILABLE", "ACL management is fenced", 503)

    def finalize(self, cursor):
        current = self.preparation.contexts.current(self.actor)
        if current is None or self.epoch is None or current["context_epoch"] != self.epoch:
            raise ContractError("SUBJECT_UNAVAILABLE", "Management subject changed", 503)

    def list_target(self, reference, *, limit=50, after=None):
        self.preparation.prepare(self.actor)
        self.epoch = None
        try:
            return self.rules.list_target(reference, limit=limit, after=after)
        finally:
            self.epoch = None
            self.current_subject = None
            self.is_owner = False
            self.is_library_admin = False
            self.is_global_library_admin = False

    def list_library(self, repo_id, *, limit=50, after=None):
        self.preparation.prepare(self.actor)
        self.epoch = None
        try:
            return self.rules.list_library(repo_id, limit=limit, after=after)
        finally:
            self.epoch = None
            self.current_subject = None
            self.is_owner = False
            self.is_library_admin = False
            self.is_global_library_admin = False

    def mutate(self, reference, **arguments):
        # Refresh outside the rule transaction; projection must not start/commit
        # another transaction while mutation effects are pending on this connection.
        self.preparation.prepare(self.actor)
        self.epoch = None
        try:
            return self.rules.mutate(reference, **arguments)
        finally:
            self.epoch = None
            self.current_subject = None
            self.is_owner = False
            self.is_library_admin = False
            self.is_global_library_admin = False



class DirectoryManagement(LibraryOwnerManagement):
    """Library authority over content rules; no directory administrator assignments."""
    def __init__(self, preparation, core, *, request_id, cloud_mode):
        if not isinstance(preparation, SubjectPreparation):
            raise ValueError("real subject preparation required")
        self.native_qualification = NativeLibraryQualification(
            native_schema=preparation.state.native_schema,
            native_table=preparation.projector.native_table, cloud_mode=cloud_mode)
        super().__init__(preparation, core, request_id=request_id)

    def qualification(self, cursor, reference, username, owner):
        return self.native_qualification.read(cursor, repo_id=reference["repo_id"],
            username=username, owner=owner)

    def decision_allowed(self, decision):
        # A library owner must be able to repair an ACL deny. This authority only
        # mutates policy; ContentReadAuthority overrides this and still enforces C read/write.
        return self.can_manage_library()

    # Directory ACL administration inherits library ownership, never stored directory grants.
    # Keeping obsolete rows cannot re-enable delegated authority.
    def scope_allowed(self, reference):
        return self.can_manage_library()

    def authorize_change(self, cursor, actor, reference, previous, value):
        return actor == self.actor and self.can_manage_library()
