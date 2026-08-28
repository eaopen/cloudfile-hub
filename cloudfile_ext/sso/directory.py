# -*- coding: utf-8 -*-
"""Where group membership comes from.

Same shape as directory ACL rule sources, and for the same reason: what the
enterprise already maintains -- an LDAP tree, an OA platform, an IdP's group
claims -- differs per deployment, while what CloudFile does with it does not.
So the *source* is a provider, selected with ``CF_PROVIDER_SSO_DIRECTORY``, and
everything downstream of it is fixed.

    directory ──pull──> cf_sso_group_map + ccnet groups ──> sharing, ACL, quota

**Pull, never intercept.** The tempting alternative is to read group claims out
of the SSO assertion as the user logs in. It is not done here, for three
reasons that are worth stating because the idea keeps coming back:

1. The claims are not reachable without patching upstream. Seahub's OAuth and
   SAML views consume the assertion locally and emit ``user_logged_in`` with
   only ``request`` and ``user``. Getting the claims out means editing
   ``seahub/oauth/views.py``, and this fork's whole cost model is the count of
   upstream files it edits.
2. Claims only describe whoever just logged in. A group has to be complete to
   be useful for sharing -- you cannot share a library with "the members who
   have signed in since Tuesday".
3. It puts the identity provider on the login path for a second reason beyond
   authentication. When it is slow, logins are slow; when its group service is
   down, membership is wrong at exactly the moment somebody is trying to work.

Pulling costs eventual consistency instead: a directory change applies at the
next tick, or in seconds if the far end calls the webhook. That is the one real
compromise in this design and it is stated in docs/sso-mapping.md rather than
buried here.
"""

import logging

logger = logging.getLogger(__name__)

#: Provider kind. cloudfile_ext.providers derives CF_PROVIDER_SSO_DIRECTORY
#: from it, so the baseline needs to know nothing about this string.
KIND = 'sso_directory'

STATIC = 'static'
EXTERNAL_SERVICE = 'external-service'

#: Name under which cloudfile_ext.external_service looks for
#: CF_SERVICE_SSO_DIRECTORY_{URL,SECRET,TIMEOUT,RETRIES,ON_FAILURE}.
SERVICE_NAME = 'SSO_DIRECTORY'


class DirectoryError(Exception):
    """The directory could not be read, or answered with something unusable.

    Raised rather than returning an empty snapshot: the reconciler treats an
    empty snapshot as a fact about the world, and a failed call is not one.
    """


class Directory(object):
    """A source of group membership.

    ``groups()`` returns the whole picture. Two shapes are accepted, so a
    provider can adopt the hierarchical contract (decision 2026-08-27 §3)
    without a coordinated upgrade::

        # flat, the original contract -- still fully valid
        [{'external_id': 'eng', 'name': 'Engineering',
          'members': ['alice@example.com', ...]}, ...]

        # hierarchical
        {'revision': 'org-20260827-0001',
         'groups': [{'external_id': 'dept-rd', 'name': '研发部',
                     'subject_type': 'dept', 'parent_external_id': 'dept-root',
                     'members': [...]},
                    {'external_id': 'role-reviewer', 'name': '评审员',
                     'subject_type': 'group', 'members': [...]}]}

    ``subject_type`` defaults to 'group'; ``parent_external_id`` defaults to
    None. A dept without a parent is created as a top-level department, a dept
    with one as its sub-department (parents must precede children or be
    already mapped -- the sync orders creates topologically either way).
    ``revision`` is optional; when present and unchanged the sync skips
    idempotently.

    Members are login strings as the directory knows them; resolving those to
    the identity Seafile enforces against is the service layer's job
    (cloudfile_ext.acl.subjects), not the provider's -- a backend should not
    have to know that Seafile 14 separated identity from email.
    """

    def groups(self):
        raise NotImplementedError

    def groups_for_user(self, login):
        """External ids this user belongs to, or None if the source cannot say.

        Only used by the refresh on login, which is an optimisation. Returning
        None is a legitimate answer -- a flat export has no per-user query --
        and simply means that user waits for the next full tick.
        """
        return None


class StaticDirectory(Directory):
    """Groups declared in configuration.

    For a deployment whose org chart is small, stable, and already known to
    whoever writes the compose file -- and it is what the capability gate
    exercises, since it makes the full pipeline (plan, ccnet writes, visible
    membership) reachable without standing up a second service.

    Not a stub: it is the complete implementation of "the directory is the
    config file". A source that cannot answer is not registered at all --
    see the note in cloudfile_ext.acl.sources about why an empty answer is the
    worst possible failure mode.
    """

    def __init__(self, groups=None):
        self._groups = groups

    def _declared(self):
        if self._groups is not None:
            return self._groups
        from django.conf import settings
        return getattr(settings, 'CF_SSO_DIRECTORY_STATIC', []) or []

    def groups(self):
        declared = self._declared()
        if not isinstance(declared, (list, tuple)):
            raise DirectoryError(
                'CF_SSO_DIRECTORY_STATIC must be a list of '
                "{'external_id', 'name', 'members'} dicts, got %r"
                % type(declared).__name__)
        return [dict(entry) for entry in declared]

    def groups_for_user(self, login):
        login = (login or '').strip().lower()
        return [g['external_id'] for g in self.groups()
                if login in {(m or '').strip().lower()
                             for m in g.get('members') or []}]


class ExternalServiceDirectory(Directory):
    """Groups fetched from the customer's own service.

    Two endpoints, both GET, both off the request path::

        GET <url>/groups              -> {"groups": [{external_id, name, members}]}
        GET <url>/users/<login>/groups -> {"groups": ["eng", ...]}

    The second is optional; a service that does not implement it returns 404
    and the user simply waits for the next full sync.

    Authentication, timeout, retry and failure policy all come from
    cloudfile_ext.external_service, which is where they belong -- this class
    only knows the two paths and the response shape.
    """

    def __init__(self, service=None):
        self._service = service

    def _client(self):
        if self._service is not None:
            return self._service
        from cloudfile_ext.external_service import ExternalService
        service = ExternalService.from_settings(SERVICE_NAME)
        if service is None:
            raise DirectoryError(
                'CF_PROVIDER_SSO_DIRECTORY=%s but CF_SERVICE_SSO_DIRECTORY_URL '
                'is not set, so there is nothing to call.' % EXTERNAL_SERVICE)
        return service

    def groups(self):
        from cloudfile_ext.external_service import ExternalServiceError
        try:
            payload = self._client().call('/groups', method='GET')
        except ExternalServiceError as exc:
            raise DirectoryError(str(exc))

        if payload is None:
            # The service is configured to fail open. That is a fine policy for
            # "carry on without this", but here "carrying on" would mean
            # syncing against nothing, so it is turned back into an error.
            raise DirectoryError(
                'directory service unreachable and configured to fail open; '
                'skipping this sync rather than treating "no answer" as '
                '"no groups"')

        groups = payload.get('groups')
        if not isinstance(groups, list):
            raise DirectoryError(
                "directory service returned no 'groups' list: %r" % (payload,))
        # Return the whole payload, not just the list: a hierarchical feed
        # wraps the list with 'revision', which build_plan reads. A flat feed
        # has nothing else in the payload, so this is a no-op for it.
        return payload

    def groups_for_user(self, login):
        from cloudfile_ext.external_service import ExternalServiceError
        try:
            payload = self._client().call(
                '/users/%s/groups' % login, method='GET')
        except (ExternalServiceError, DirectoryError) as exc:
            # A per-user refresh is a nicety; the full sync is the contract.
            logger.info('per-user directory lookup for %s failed: %s',
                        login, exc)
            return None
        if not payload:
            return None
        groups = payload.get('groups')
        return groups if isinstance(groups, list) else None


_STATIC = StaticDirectory()
_EXTERNAL = ExternalServiceDirectory()


def register(registry):
    """Register both sources. Registering does not select either of them."""
    registry.register_provider(KIND, STATIC, _STATIC)
    registry.register_provider(KIND, EXTERNAL_SERVICE, _EXTERNAL)


def selected_name():
    """Which source the operator picked, or '' -- for the status endpoint."""
    from cloudfile_ext import providers

    return providers.selected(KIND)


def active(registry):
    """The selected source, or None when the operator has chosen none.

    None is not an error: CF_ENABLE_SSO can be on purely to configure upstream's
    OAuth/SAML login, with no group mapping wanted. The sync task checks for
    None and does nothing, rather than inventing a default -- guessing which
    directory an enterprise meant is not a thing this code can do.
    """
    from cloudfile_ext import providers

    if not providers.selected(KIND):
        return None
    return registry.providers.active(KIND)
