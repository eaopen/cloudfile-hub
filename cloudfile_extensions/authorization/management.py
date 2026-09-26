"""Real library-owner ACL management; delegation/recovery are not implicit.

Already authenticated actor, current subject and all effect rows share authority.
No public route, administrator bypass, other-connection permission RPC or UI.
"""
from ..common.errors import ContractError
from ..directory.preparation import SubjectPreparation
from .core import PolicyCore
from .rules import ACLRules
from .admins import DirectoryAdmins


class LibraryOwnerManagement:
    def __init__(self, preparation, core, *, request_id):
        if not isinstance(preparation, SubjectPreparation) or not isinstance(core, PolicyCore):
            raise ValueError("real subject preparation and native policy core required")
        self.preparation, self.core = preparation, core
        self.state = preparation.state
        self.actor = preparation.actor
        self.epoch = None
        self.rules = ACLRules(self.state.connection, provider=self.state.provider,
            actor=self.actor, request_id=request_id, authorize=self.authorize,
            finalize=self.finalize)
        self.admins = DirectoryAdmins(self.state.connection, provider=self.state.provider,
            actor=self.actor, request_id=request_id, authorize=self.authorize, finalize=self.finalize)

    def authorize(self, cursor, actor, reference):
        if actor != self.actor:
            return False
        current = self.preparation.contexts.current(actor)
        if current is None:
            raise ContractError("SUBJECT_UNAVAILABLE", "Current subject must be prepared", 503)
        self.epoch = current["context_epoch"]
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
        if cursor.fetchall() != ((username,),):
            return False
        for table in ("Repo", "RepoInfo", "VirtualRepo", "RepoOwner"):
            cursor.execute("SELECT ENGINE FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name=%s", (table,))
            if cursor.fetchall() != (("InnoDB",),):
                raise ContractError("POLICY_UNAVAILABLE", "Management library is unavailable", 503)
        self._barriers(repo)
        decision = self.core.evaluate(reference, provider=self.state.provider,
            subject=current["subject"], rules=self.rules.candidates(reference, locking=True),
            ce_permission="rw", attribute_allowlist=self.preparation.contexts.allowlist)
        # Manage is separate but cannot reveal/override explicit content denial.
        return decision["visible"] and decision["read"]

    def _barriers(self, repo):
        if (self.state.barrier_active(self.state.provider, self.actor) or
                self.state.jobs.active_barrier(dict(type="repo", provider="cloudfile", external_id=repo))):
            raise ContractError("SUBJECT_UNAVAILABLE", "ACL management is fenced", 503)

    def finalize(self, cursor):
        current = self.preparation.contexts.current(self.actor)
        if current is None or self.epoch is None or current["context_epoch"] != self.epoch:
            raise ContractError("SUBJECT_UNAVAILABLE", "Management subject changed", 503)

    def mutate(self, reference, **arguments):
        # Refresh outside the rule transaction; projection must not start/commit
        # another transaction while mutation effects are pending on this connection.
        self.preparation.prepare(self.actor)
        self.epoch = None
        try:
            return self.rules.mutate(reference, **arguments)
        finally:
            self.epoch = None

    def mutate_admin(self, reference, **arguments):
        self.preparation.prepare(self.actor)
        self.epoch = None
        try:
            return self.admins.mutate(reference, **arguments)
        finally:
            self.epoch = None
