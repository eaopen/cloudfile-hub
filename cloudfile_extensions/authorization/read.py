"""Transactional metadata read authority; not a file transfer ticket issuer."""
from ..common.errors import ContractError
from ..jobs.authority import scope_locks
from ..resources.paths import resource_ref
from .management import DirectoryManagement


class ContentReadAuthority(DirectoryManagement):
    def scope_allowed(self, reference):
        # Ordinary content reads require CE qualification and C visible/read,
        # not a directory-management delegation. No management write is granted.
        return True

    def authorize_change(self, cursor, actor, reference, previous, value):
        return False

    def mutate(self, *args, **kwargs):
        raise ContractError("ACCESS_DENIED", "Read authority cannot change policy", 403)

    def mutate_admin(self, *args, **kwargs):
        raise ContractError("ACCESS_DENIED", "Read authority cannot change delegation", 403)

    def list_target(self, *args, **kwargs):
        raise ContractError("ACCESS_DENIED", "Read authority cannot inspect management rules", 403)

    def consume(self, reference, reader):
        """Trusted bounded metadata reader(cursor, reference) in this transaction.

        Reader must not commit, reconnect, perform DDL, stream files or issue
        tickets. It must verify actual resource UID/lifecycle before metadata use.
        An earlier authorization boolean must never substitute for this scope.
        """
        if not callable(reader):
            raise ValueError("transactional metadata reader required")
        ref = resource_ref(reference)
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
                        if self.authorize(cursor, self.actor, ref) is not True:
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
