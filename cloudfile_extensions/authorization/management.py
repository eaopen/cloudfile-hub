"""Real owner/delegated directory management; recovery is not implicit.

Already authenticated actor, current subject and all effect rows share authority.
No public route, administrator bypass, other-connection permission RPC or UI.
"""
from ..common.errors import ContractError
from ..directory.preparation import SubjectPreparation
from .core import PolicyCore
from .rules import ACLRules
from .admins import DirectoryAdmins
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
        self.rules = ACLRules(self.state.connection, provider=self.state.provider,
            actor=self.actor, request_id=request_id, authorize=self.authorize,
            finalize=self.finalize, authorize_change=self.authorize_change)
        self.admins = DirectoryAdmins(self.state.connection, provider=self.state.provider,
            actor=self.actor, request_id=request_id, authorize=self.authorize, finalize=self.finalize,
            authorize_change=self.authorize_change)

    def authorize(self, cursor, actor, reference):
        if actor != self.actor:
            return False
        current = self.preparation.contexts.current(actor)
        if current is None:
            raise ContractError("SUBJECT_UNAVAILABLE", "Current subject must be prepared", 503)
        self.epoch = current["context_epoch"]
        self.current_subject = current["subject"]
        username = self.state.username(actor)
        cursor.execute("SELECT email,is_active FROM " + self.state.accounts + " WHERE email=%s FOR UPDATE", (username,))
        if cursor.fetchall() != ((username, 1),):
            return False
        cursor.execute("SELECT user,login_id FROM " + self.state.profiles + " WHERE user=%s OR login_id=%s FOR UPDATE", (username, actor))
        if cursor.fetchall() != ((username, actor),):
            return False
        for schema, table in ((self.state.native_schema, "EmailUser"),
                              (self.state.identity_schema, "profile_profile")):
            cursor.execute("SELECT ENGINE FROM information_schema.tables WHERE table_schema=%s AND table_name=%s", (schema, table))
            if cursor.fetchall() != (("InnoDB",),):
                raise ContractError("POLICY_UNAVAILABLE", "Management identity is unavailable", 503)
        repo = reference["repo_id"]
        cursor.execute("SELECT repo_id FROM Repo WHERE repo_id=%s FOR UPDATE", (repo,))
        if cursor.fetchall() != ((repo,),):
            return False
        cursor.execute("SELECT status FROM RepoInfo WHERE repo_id=%s FOR UPDATE", (repo,))
        if cursor.fetchall() != ((0,),):
            return False
        cursor.execute("SELECT repo_id FROM VirtualRepo WHERE repo_id=%s FOR UPDATE", (repo,))
        if cursor.fetchall():
            return False
        cursor.execute("SELECT owner_id FROM RepoOwner WHERE repo_id=%s FOR UPDATE", (repo,))
        owners = cursor.fetchall()
        if len(owners) != 1 or not isinstance(owners[0][0], str) or not owners[0][0]:
            return False
        owner = owners[0][0]
        self.is_owner = owner == username
        for table in ("Repo", "RepoInfo", "VirtualRepo", "RepoOwner"):
            cursor.execute("SELECT ENGINE FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name=%s", (table,))
            if cursor.fetchall() != (("InnoDB",),):
                raise ContractError("POLICY_UNAVAILABLE", "Management library is unavailable", 503)
        self._barriers(repo)
        permission = self.qualification(cursor, reference, username, owner)
        if permission is None or not self.scope_allowed(reference):
            return False
        decision = self.core.evaluate(reference, provider=self.state.provider,
            subject=current["subject"], rules=self.rules.candidates(reference, locking=True),
            ce_permission=permission, attribute_allowlist=self.preparation.contexts.allowlist)
        # Manage is separate but cannot reveal/override explicit content denial.
        return decision["visible"] and decision["read"]

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

    def list_target(self, reference, *, admins=False, limit=50, after=None):
        if type(admins) is not bool:
            raise ValueError("explicit policy domain required")
        self.preparation.prepare(self.actor)
        self.epoch = None
        try:
            store = self.admins if admins else self.rules
            return store.list_target(reference, limit=limit, after=after)
        finally:
            self.epoch = None
            self.current_subject = None
            self.is_owner = False

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

    def mutate_admin(self, reference, **arguments):
        self.preparation.prepare(self.actor)
        self.epoch = None
        try:
            return self.admins.mutate(reference, **arguments)
        finally:
            self.epoch = None
            self.current_subject = None
            self.is_owner = False


class DirectoryManagement(LibraryOwnerManagement):
    """Owner or current delegated scope; never a full-library policy API."""
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

    def _scopes(self, reference):
        if self.current_subject is None:
            return []
        return self.admins.scopes(reference, subject=self.current_subject,
            attribute_allowlist=self.preparation.contexts.allowlist, locking=True)

    def scope_allowed(self, reference):
        return self.is_owner or DirectoryAdmins.permits(self._scopes(reference), reference)

    def authorize_change(self, cursor, actor, reference, previous, value):
        if actor != self.actor or self.current_subject is None:
            return False
        if self.is_owner:
            return True
        scopes = self._scopes(reference)
        # Removing an old inherited rule changes descendants too. Check both
        # sides, not only the new body; also protects delete and self-delegation.
        inherited_effect = any(item is not None and item["inherit"] for item in (previous, value))
        return DirectoryAdmins.permits(scopes, reference, inherit=inherited_effect)
