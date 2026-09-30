"""Transactional metadata read authority; not a file transfer ticket issuer."""
from ..common.errors import ContractError
from ..jobs.authority import scope_locks
from ..resources.paths import resource_ref
from .management import DirectoryManagement


class ContentReadAuthority(DirectoryManagement):
    def requires_library_admin(self):
        # Ordinary file reads do not depend on Seahub's management tables.
        return bool(getattr(self, "_management_diagnostic", False))

    def requires_system_admin(self):
        return bool(getattr(self, "_management_diagnostic", False))

    def system_admin_qualification_override(self):
        return False

    def library_status_allowed(self, status):
        # Native read-only affects writes, not otherwise-authorized reads.
        # Suspended/unknown states never qualify.
        return status in (0, 1)

    def qualification(self, cursor, reference, username, owner):
        self.native_permission = super().qualification(cursor, reference, username, owner)
        return self.native_permission

    def decision_allowed(self, decision):
        self.effective_visible = bool(decision["visible"])
        self.effective_access = {"read": bool(decision["visible"] and decision["read"]),
            "write": bool(decision["visible"] and decision["write"])}
        return self.effective_access["read"]

    def scope_allowed(self, reference):
        # Ordinary content reads require CE qualification and C visible/read,
        # not a directory-management delegation. No management write is granted.
        return True

    def authorize_change(self, cursor, actor, reference, previous, value):
        return False

    def mutate(self, *args, **kwargs):
        raise ContractError("ACCESS_DENIED", "Read authority cannot change policy", 403)

    def list_target(self, *args, **kwargs):
        raise ContractError("ACCESS_DENIED", "Read authority cannot inspect management rules", 403)

    def inspect_policy(self, reference):
        """Inspect this authenticated actor's C decision, never target metadata or another user."""
        def diagnostic(cursor, ref):
            decision = self.effective_access
            permission = ('invisible' if not self.effective_visible else 'rw' if decision['write']
                          else 'r' if decision['read'] else 'none')
            return dict(native_permission=self.native_permission, effective_permission=permission,
                        can_manage=self.can_manage_library())
        return self._consume(reference, diagnostic, diagnostic=True)

    def consume(self, reference, reader):
        return self._consume(reference, reader, diagnostic=False)

    def consume_many(self, references, *, batch_size=20, reader=None):
        """Evaluate bounded groups, optionally consuming metadata before commit.

        Without reader, preserve the ordered permission/None list. A trusted
        reader(cursor, references, accesses) receives only readable targets and
        must return equally ordered values; denied slots remain None. It obeys
        consume's same-connection/no-commit contract, not a deferred grant.
        """
        if (type(self) is not ContentReadAuthority or not isinstance(references, (list, tuple)) or
                type(batch_size) is not int or not 1 <= batch_size <= 50 or
                (reader is not None and not callable(reader))):
            raise ValueError("bounded content-read batch required")
        if not references:
            return []
        refs = [resource_ref(reference) for reference in references]
        repo = refs[0]["repo_id"]
        if any(ref["repo_id"] != repo for ref in refs):
            raise ValueError("content-read batch must belong to one library")
        self.preparation.prepare(self.actor)
        connection = self.state.connection
        scopes = [dict(type="provider", provider=self.state.provider, external_id=self.state.provider),
                  dict(type="user", provider=self.state.provider, external_id=self.actor),
                  dict(type="repo", provider="cloudfile", external_id=repo)]
        permissions = []
        try:
            for start in range(0, len(refs), batch_size):
                group = refs[start:start + batch_size]
                self.native_permission = None
                self.effective_access = None
                self._management_diagnostic = False
                with scope_locks(connection, scopes):
                    connection.begin()
                    try:
                        with connection.cursor() as cursor:
                            # No first-object decision is used as a group grant.
                            permission = self.prepare_authorization(cursor, self.actor, group[0])
                            group_results = [None] * len(group)
                            authorized, accesses, positions = [], [], []
                            if permission in ("r", "rw") and self.current_subject is not None:
                                candidates = self.rules.candidates_many(group, locking=True)
                                if len(candidates) != len(group):
                                    raise ContractError("POLICY_UNAVAILABLE", "Incomplete batch candidates", 503)
                                for index, (ref, rules) in enumerate(zip(group, candidates)):
                                    decision = self.core.evaluate(ref, provider=self.state.provider,
                                        subject=self.current_subject, rules=rules,
                                        ce_permission=permission,
                                        attribute_allowlist=self.preparation.contexts.allowlist,
                                        hard_readonly=self.hard_readonly)
                                    allowed = self.decision_allowed(decision) and self.scope_allowed(ref)
                                    if allowed:
                                        group_results[index] = "rw" if self.effective_access["write"] else "r"
                                        authorized.append(dict(ref))
                                        accesses.append(dict(self.effective_access))
                                        positions.append(index)
                            if reader is not None and authorized:
                                values = reader(cursor, authorized, accesses)
                                if not isinstance(values, (list, tuple)) or len(values) != len(authorized):
                                    raise ContractError("POLICY_UNAVAILABLE", "Incomplete batch metadata", 503)
                                for index, value in zip(positions, values):
                                    group_results[index] = value
                            # Recheck at the effect boundary, while the same repo
                            # guard and transaction still protect every read.
                            self._barriers(repo)
                            self.finalize(cursor)
                        connection.commit()
                        permissions.extend(group_results)
                    finally:
                        connection.rollback()
            return permissions
        except ContractError:
            raise
        except Exception:
            raise ContractError("POLICY_UNAVAILABLE", "Resource read authority is unavailable", 503) from None
        finally:
            self.epoch = None
            self.current_subject = None
            self.is_owner = False
            self.is_library_admin = False
            self.is_global_library_admin = False
            self.effective_access = None
            self.effective_visible = None
            self.native_permission = None
            self._management_diagnostic = False

    def _consume(self, reference, reader, *, diagnostic):
        """Trusted bounded metadata reader(cursor, reference) in this transaction.

        Reader must not commit, reconnect, perform DDL, stream files or issue
        native file-transfer tickets. Device-bound local-session claim inputs
        remain metadata and cannot themselves release bytes or publish content.
        It must verify actual resource UID/lifecycle before metadata use.
        An earlier authorization boolean must never substitute for this scope.
        """
        if not callable(reader):
            raise ValueError("transactional metadata reader required")
        ref = resource_ref(reference)
        self.effective_access = None
        self.effective_visible = None
        self.native_permission = None
        self._management_diagnostic = diagnostic
        self.preparation.prepare(self.actor)
        connection = self.state.connection
        scopes = [dict(type="provider", provider=self.state.provider, external_id=self.state.provider),
                  dict(type="user", provider=self.state.provider, external_id=self.actor),
                  dict(type="repo", provider="cloudfile", external_id=ref["repo_id"])]
        try:
            with scope_locks(connection, scopes):
                connection.begin()
                try:
                    with connection.cursor() as cursor:
                        allowed = self.authorize(cursor, self.actor, ref)
                        if allowed is not True and (not diagnostic or self.effective_access is None):
                            raise ContractError("ACCESS_DENIED", "Resource read is not allowed", 403)
                        result = reader(cursor, ref)
                        self.finalize(cursor)
                    connection.commit()
                    return result
                finally:
                    connection.rollback()
        except ContractError:
            raise
        except Exception:
            raise ContractError("POLICY_UNAVAILABLE", "Resource read authority is unavailable", 503) from None
        finally:
            self.epoch = None
            self.current_subject = None
            self.is_owner = False
            self.is_library_admin = False
            self.is_global_library_admin = False
            self.effective_access = None
            self.effective_visible = None
            self.native_permission = None
            self._management_diagnostic = False


class ContentMetadataWriteAuthority(ContentReadAuthority):
    """Same-cursor metadata mutation authority, never native bytes publication.

    Uses the identical C policy result, including CE qualification, explicit
    denial and hard native read-only state. Caller must additionally resolve
    actual UID/lifecycle in the consumed transaction. No management bypass.
    """
    def decision_allowed(self, decision):
        return decision["visible"] and decision["write"]

    def library_status_allowed(self, status):
        return status == 0


class LibraryWideManagementAuthority(ContentReadAuthority):
    """Whole-library management, not an exact root or subdirectory grant."""
    def requires_library_admin(self):
        return True

    def requires_system_admin(self):
        return True

    def system_admin_qualification_override(self):
        return True

    def library_status_allowed(self, status):
        return status == 0

    def decision_allowed(self, decision):
        # Management may repair a content deny without gaining content access.
        return self.can_manage_library()

    def _scopes(self, reference):
        # Job coordination scopes are locks, not former directory grants.
        return [dict(type="provider", provider=self.state.provider, external_id=self.state.provider),
                dict(type="user", provider=self.state.provider, external_id=self.actor),
                dict(type="repo", provider="cloudfile", external_id=reference["repo_id"])]

    def scope_allowed(self, reference):
        # Tag definitions require library authority; a former directory grant is ignored.
        return reference["kind"] == "dir" and reference["path"] == "/" and self.can_manage_library()


class LibraryTagManagementAuthority(LibraryWideManagementAuthority):
    """Shared tag definitions use the whole-library management boundary."""
