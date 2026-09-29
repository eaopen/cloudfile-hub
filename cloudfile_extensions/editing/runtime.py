"""Explicit editing service assembly; no routes or capability enablement."""
from contextlib import contextmanager
import hmac
import json
import re

from ..common.validation import identifier
from ..resources.runtime import ResourceServiceFactory
from .service import EditingService
from .authority import LockManagementAuthority
from ..common.errors import ContractError


def native_file_version(sql, reference, evidence):
    """Read one native file from the Branch row already pinned by lifecycle."""
    from seaserv import seafile_api
    sql.execute("SELECT commit_id FROM Branch WHERE repo_id=%s AND name='master' FOR UPDATE",
                (reference['repo_id'],))
    rows = sql.fetchall()
    if len(rows) != 1:
        raise ContractError('PATH_STATE_PENDING', 'Native head is unavailable', 503)
    value = seafile_api.get_file_id_by_commit_and_path(
        reference['repo_id'], rows[0][0], reference['path'])
    if not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{40}', value):
        raise ContractError('PATH_STATE_PENDING', 'Native file is unavailable', 503)
    return value


def native_session_holder(request, resources):
    from ..identity.read_ticket_http import native_download_actor
    actor = native_download_actor(request)
    if (actor.user_id != resources.write_authority.actor or
            actor.native_username != resources.write_authority.state.username(actor.user_id)):
        raise ContractError('AUTHENTICATION_REQUIRED', 'Editing identity changed', 401)
    key = request.session.session_key
    if not isinstance(key, str) or not key:
        raise ContractError('AUTHENTICATION_REQUIRED', 'Editing session is unavailable', 401)
    return key


class EditingFactory:
    def __init__(self, *, resources, holder_reader, version_reader, source="web"):
        if (not isinstance(resources, ResourceServiceFactory) or not callable(holder_reader) or
                not callable(version_reader)):
            raise ValueError("actual resource factory and trusted session/version readers required")
        self.resources, self.holder_reader, self.version_reader = resources, holder_reader, version_reader
        self.source = source

    @contextmanager
    def __call__(self, request, request_id):
        with self.resources(request, request_id) as resources:
            # This provider resolves the authenticated native session/device;
            # it must not return a browser body/header holder or only userId.
            # Two sessions of one employee are distinct holders.
            holder = self.holder_reader(request, resources)
            identifier(holder, maximum=512)
            # Never expose a native session key or device credential as a public
            # holder ID. Domain-separated HMAC retains stable session isolation.
            holder = hmac.digest(resources.store.secret, json.dumps([
                "cf.lock.holder.v1", resources.write_authority.state.provider,
                resources.write_authority.actor, holder], ensure_ascii=False,
                separators=(",", ":")).encode("utf-8"), "sha256").hex()
            management = LockManagementAuthority(resources.read_authority.preparation,
                self.resources.core, request_id=request_id, cloud_mode=self.resources.cloud_mode)
            try:
                yield EditingService(resources, holder=holder, version_reader=self.version_reader,
                    source=self.source, management=management)
            finally:
                management.epoch = None
                management.current_subject = None
                management.is_owner = False
                management.effective_access = None
