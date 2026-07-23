# -*- coding: utf-8 -*-
"""SSO login and user/organisation mapping.

**The login half is upstream's, and stays upstream's.** Seafile CE 14.0 ships
OAuth2/OIDC (``seahub/oauth/``), SAML (``seahub/adfs_auth/``), CAS, LDAP and
REMOTE_USER, none of it behind a Pro check. Writing another one here would mean
maintaining a second authentication path forever in order to end up where the
fork already was. What CloudFile adds is the part that is missing:

* **Configuration.** Upstream expects an operator to hand-edit
  ``conf/seahub_settings.py``. CloudFile deployments configure everything from
  the compose ``.env``, and the config block is rewritten on every start, so
  ``CF_ENABLE_SSO`` plus a handful of ``CF_SSO_*`` variables is the whole
  interface. That part lives in cloudfile-docker's bootstrap, not here.

* **Organisation mapping.** Upstream maps user *attributes* -- display name,
  contact email, login id -- and nothing else. Which teams somebody belongs to
  is not derived from the IdP at all, except in the WeCom and DingTalk
  integrations, whose ``external_department`` table is keyed by a BIGINT and so
  cannot hold a generic directory's group ids. So group membership is what this
  package does: pull the org chart, mirror it into Seafile groups, and let
  sharing, quotas and directory ACL keep reading groups exactly as they do now.

Nothing here touches an upstream file. The registration below uses only seams
the baseline already provides, plus ``seahub.auth.signals.user_logged_in``,
which is upstream's own signal.

See cloudfile-docker/docs/sso-mapping.md for the semantics and for the one
compromise this design makes (eventual consistency).
"""

import logging

logger = logging.getLogger(__name__)

#: How long a login may go without a per-user directory refresh, in seconds.
#: The refresh is a nicety on top of the periodic sync; this cache entry is
#: what stops a page full of API calls turning one login into fifty lookups.
LOGIN_REFRESH_TTL = 600


def register(registry):
    from cloudfile_ext.features import is_enabled

    if not is_enabled('CF_ENABLE_SSO'):
        return

    from django.urls import path

    from cloudfile_ext.sso import directory, service
    from cloudfile_ext.sso.apis import (
        AdminSSOGroupMapView, AdminSSOSyncView, SSODirectoryWebhookView,
    )

    directory.register(registry)

    registry.register_urls([
        path('api/v2.1/admin/cloudfile/sso/sync/',
             AdminSSOSyncView.as_view(), name='cloudfile-admin-sso-sync'),
        path('api/v2.1/admin/cloudfile/sso/group-map/',
             AdminSSOGroupMapView.as_view(),
             name='cloudfile-admin-sso-group-map'),
        path('api/v2.1/cloudfile/sso/directory-webhook/',
             SSODirectoryWebhookView.as_view(),
             name='cloudfile-sso-directory-webhook'),
    ])

    registry.register_menu({
        'key': 'sso',
        'label': 'Directory mapping',
        'url': '/sys/cloudfile/sso/',
        'feature': 'CF_ENABLE_SSO',
    })

    # The scheduled full sync is the contract; everything else is latency
    # reduction on top of it.
    registry.register_periodic_task(
        service.SYNC_TASK, _sync_interval(), service.sync)

    _connect_login_refresh()


def _sync_interval():
    from django.conf import settings

    try:
        return max(60, int(getattr(settings, 'CF_SSO_SYNC_INTERVAL', 600)))
    except (TypeError, ValueError):
        logger.warning('CF_SSO_SYNC_INTERVAL is not a number; using 600s')
        return 600


def _connect_login_refresh():
    """Refresh the person who just logged in, when their source can say.

    Connected to a signal rather than called from a view because there is no
    view here to call it from -- the login flows belong to upstream. The signal
    is upstream's own and carries no claims, which is precisely why this
    re-reads the directory instead of trusting the assertion; see
    cloudfile_ext.sso.directory.

    Failures are swallowed. A directory that is slow or down must not be able to
    stop people logging in: the periodic sync catches up either way, and a login
    that failed because a *group* lookup failed would be an outage manufactured
    by an optimisation.
    """
    from django.core.cache import cache
    from django.dispatch import receiver

    from seahub.auth.signals import user_logged_in

    from cloudfile_ext.sso import service

    @receiver(user_logged_in, dispatch_uid='cloudfile_sso_login_refresh')
    def _on_login(sender, request=None, user=None, **kwargs):
        username = getattr(user, 'username', None)
        if not username:
            return
        key = 'cf_sso_login_refresh:%s' % username
        if cache.get(key):
            return
        cache.set(key, 1, LOGIN_REFRESH_TTL)
        try:
            service.sync_user(username)
        except Exception:
            logger.exception('SSO refresh on login failed for %s', username)

    # Keep a reference so the receiver survives. Django holds receivers weakly,
    # and a function defined inside another function has no other owner -- it
    # would be collected when ready() returns and the signal would then simply
    # never fire, with nothing anywhere to say why.
    _connect_login_refresh.receiver = _on_login
