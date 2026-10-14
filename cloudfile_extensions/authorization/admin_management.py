"""Native system account authority for administrator-only policy commands."""
import os
from ..common.errors import ContractError
from .host import PolicyHost
from .resources import PolicyResources
from ..directory.native_state import NativeSubjectState
from ..directory.project import qualified
from .management import DirectoryManagement
from .rules import ACLRules

def admin_resources(host):
    if (not isinstance(host, PolicyHost) or host.pid != os.getpid()
            or host.closed or host.draining):
        raise ContractError('POLICY_UNAVAILABLE', 'Administrator policy host is unavailable', 503)
    resources = getattr(host.deployment.factory, 'resources', None)
    if not isinstance(resources, PolicyResources):
        raise ContractError('POLICY_UNAVAILABLE', 'Administrator policy storage is unavailable', 503)
    return resources


class SystemAdministratorManagement(DirectoryManagement):
    def __init__(self, resources, connection, *, username, reference, request_id,
                 authorize_library, lifecycle_reader):
        self.state = NativeSubjectState(connection, native_schema=resources.native_schema,
            identity_schema=resources.identity_schema, provider=resources.provider)
        self.actor = 'native-account:' + username
        self.username, self.reference = username, reference
        self.authorize_library = authorize_library
        self.accounts = qualified(resources.native_schema, 'EmailUser')
        self.epoch = self.current_subject = None
        self.is_owner = self.is_library_admin = self.is_global_library_admin = False
        self.rules = ACLRules(connection, provider=resources.provider, actor=self.actor,
            actor_kind='service', request_id=request_id, authorize=self.authorize,
            finalize=self.finalize, lifecycle_reader=lifecycle_reader)

    def prepare_policy_actor(self):
        # No business-user snapshot is fabricated for a native administrator.
        # The actual account and library are locked in every command below.
        return None

    def authorize(self, cursor, actor, reference):
        if actor != self.actor or reference['repo_id'] != self.reference['repo_id']:
            return False
        cursor.execute('SELECT ENGINE FROM information_schema.tables '
            'WHERE table_schema=%s AND table_name=%s', (self.state.native_schema, 'EmailUser'))
        if cursor.fetchall() != (('InnoDB',),):
            raise ContractError('POLICY_UNAVAILABLE', 'Administrator account storage is unavailable', 503)
        cursor.execute('SELECT is_active,is_staff FROM ' + self.accounts +
            ' WHERE email=%s FOR UPDATE', (self.username,))
        if cursor.fetchall() != ((1, 1),):
            return False
        repo = reference['repo_id']
        for table in ('Repo', 'RepoInfo', 'VirtualRepo', 'RepoOwner'):
            cursor.execute('SELECT ENGINE FROM information_schema.tables '
                'WHERE table_schema=DATABASE() AND table_name=%s', (table,))
            if cursor.fetchall() != (('InnoDB',),):
                raise ContractError('POLICY_UNAVAILABLE', 'Native library storage is unavailable', 503)
        cursor.execute('SELECT repo_id FROM Repo WHERE repo_id=%s FOR UPDATE', (repo,))
        if cursor.fetchall() != ((repo,),):
            return False
        cursor.execute('SELECT status FROM RepoInfo WHERE repo_id=%s FOR UPDATE', (repo,))
        status = cursor.fetchall()
        if len(status) != 1 or status[0][0] not in (0, 1):
            return False
        cursor.execute('SELECT repo_id FROM VirtualRepo WHERE repo_id=%s FOR UPDATE', (repo,))
        if cursor.fetchall():
            return False
        cursor.execute('SELECT owner_id FROM RepoOwner WHERE repo_id=%s FOR UPDATE', (repo,))
        owners = cursor.fetchall()
        if len(owners) != 1 or not isinstance(owners[0][0], str) or not owners[0][0]:
            return False
        self._barriers(repo)
        return self.authorize_library(reference) is True

    authorize_share = authorize

    def _barriers(self, repo):
        for scope in (dict(type='provider', provider=self.state.provider, external_id=self.state.provider),
                      dict(type='repo', provider='cloudfile', external_id=repo)):
            if self.state.jobs.active_barrier(scope):
                raise ContractError('POLICY_UNAVAILABLE', 'Administrator policy management is fenced', 503)

    def finalize(self, cursor):
        if self.authorize(cursor, self.actor, self.reference) is not True:
            raise ContractError('ACCESS_DENIED', 'Administrator authority changed', 403)
