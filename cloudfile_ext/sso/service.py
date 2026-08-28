# -*- coding: utf-8 -*-
"""Carry out what cloudfile_ext.sso.reconcile decided.

Split from the reconciler on purpose: everything that decides is over there,
without Django or seaserv, so it can be tested exhaustively; everything here
just does what it is told and reports what happened.

The report is not decoration. Directory mapping is eventually consistent, and
that trade is only defensible while "what did the last sync do, and when?" has
an answer -- see docs/sso-mapping.md.
"""

import logging

from cloudfile_ext.identity import UnknownSubject, resolve_user
from cloudfile_ext.sso import directory, reconcile, snapshot
from cloudfile_ext.sso.models import SSOGroupMap, SSOSyncState

logger = logging.getLogger(__name__)

#: Key for cf_sso_group_map rows and cf_sso_sync_state.
#:
#: Deliberately fixed rather than the selected provider's name: switching from
#: `static` to `external-service` against the same directory must keep the
#: existing mappings. Keying by provider name would orphan every group and
#: build a second set beside it, and the first anyone would know is that
#: sharing stopped working.
PROVIDER = 'cloudfile-sso'

SYNC_TASK = 'sso-directory-sync'

STATUS_OK = 'ok'
STATUS_REFUSED = 'refused'
STATUS_ERROR = 'error'
STATUS_SKIPPED = 'skipped'


class SyncNotConfigured(Exception):
    """Something the sync cannot invent is missing."""


def _settings():
    from django.conf import settings
    return settings


def group_owner():
    """The account that owns the groups CloudFile creates.

    Required, with no default. A group needs an owner, and picking one --
    "the first admin", say -- would silently attach every synced group to
    whoever happens to sort first, and move them all if that account is ever
    deleted. Better to refuse and have an operator name it once.
    """
    owner = getattr(_settings(), 'CF_SSO_GROUP_OWNER', '')
    if not owner:
        raise SyncNotConfigured(
            'CF_SSO_GROUP_OWNER is not set; the sync has no account to own '
            'the groups it creates.')
    try:
        return resolve_user(owner)
    except UnknownSubject:
        raise SyncNotConfigured(
            'CF_SSO_GROUP_OWNER=%r does not name an account.' % owner)


def max_removal_ratio():
    value = getattr(_settings(), 'CF_SSO_MAX_REMOVAL_RATIO',
                    reconcile.DEFAULT_MAX_REMOVAL_RATIO)
    # An explicit empty value is how an operator says "no ceiling" from a
    # compose file, where everything is a string.
    if value in ('', None):
        return None
    return float(value)


# -- reading the world -----------------------------------------------------

def _resolve_members(snapshot):
    """Map directory logins onto Seafile identities.

    Unresolvable members are dropped and *named* in the report rather than
    passed through: a login that does not exist yet is normal during a
    rollout, but a login that never resolves means the directory and Seafile
    disagree about who people are, and that has to be visible.

    Groups with unresolvable members are marked `quarantined`: the reconciler
    still receives their full membership (so joins apply), but the caller must
    not run removals for them -- otherwise a feed that misspells one login
    would read as "this person left", and the sync would faithfully revoke a
    real person's membership. The periodic sync passes the quarantine list to
    reconcile.build, which then emits no `remove` for those groups; the next
    clean snapshot lifts the quarantine.
    """
    resolved = []
    unresolved = []
    quarantined = set()
    for group in snapshot:
        members = []
        broken = False
        for login in group.get('members') or []:
            try:
                members.append(resolve_user(login))
            except UnknownSubject:
                unresolved.append(login)
                broken = True
        entry = dict(group)
        entry['members'] = members
        if broken:
            quarantined.add(entry['external_id'])
        resolved.append(entry)
    return resolved, unresolved, quarantined


def _current_state(mapped):
    """Membership and owner of each mapped group, straight from ccnet."""
    from seaserv import ccnet_api

    members = {}
    protected = {}
    stale = []
    for external_id, row in mapped.items():
        group_id = row['group_id']
        group = ccnet_api.get_group(group_id)
        if group is None:
            # Somebody deleted the group out from under us. Drop the mapping so
            # the next tick recreates it, rather than failing every tick
            # forever on a group that no longer exists.
            stale.append(external_id)
            continue
        members[group_id] = [m.user_name
                             for m in ccnet_api.get_group_members(group_id)]
        protected[group_id] = [group.creator_name]
    return members, protected, stale


# -- doing it --------------------------------------------------------------

def _apply(plan, owner):
    from seaserv import ccnet_api, seafile_api

    done = {'create': 0, 'rename': 0, 'add': 0, 'remove': 0, 'unmap': 0}
    errors = []

    # external_id -> group_id for rows written by this pass, so a sub-dept's
    # parent resolves from what the same plan created a moment ago. Existing
    # rows are seeded from the plan's rename/unmap knowledge via the mapper
    # below; creates are ordered parents-before-children by the reconciler.
    created_ids = {}

    for entry in plan.create:
        try:
            parent_id = 0
            if entry.get('subject_type') == 'dept':
                parent_external = entry.get('parent_external_id')
                if parent_external:
                    parent_gid = created_ids.get(parent_external)
                    if parent_gid is None:
                        # The parent exists from an earlier sync; look it up in
                        # the map rather than refusing -- re-parenting onto a
                        # mapped dept is the ordinary steady state.
                        row = SSOGroupMap.objects.filter(
                            provider=PROVIDER,
                            external_id=parent_external).first()
                        parent_gid = row.group_id if row else None
                    if parent_gid is None:
                        raise ValueError(
                            'parent dept %r is not mapped; the snapshot was '
                            'validated, so this means the parent create '
                            'failed earlier in this pass' % parent_external)
                    parent_id = parent_gid
                else:
                    # Top-level department: -1 in ccnet's convention, read back
                    # by cloudfile_ext.acl.service._load_subjects as dept.
                    parent_id = -1
            group_id = ccnet_api.create_group(
                entry['name'], owner, None, parent_id)
            SSOGroupMap.objects.add(
                PROVIDER, entry['external_id'], group_id, entry['name'],
                subject_type=entry.get('subject_type') or 'group',
                parent_external_id=entry.get('parent_external_id'))
            created_ids[entry['external_id']] = group_id
            done['create'] += 1
        except Exception as exc:
            errors.append('create %s: %s' % (entry['external_id'], exc))
            # Without a mapping row the members below have nowhere to go, and
            # the next tick will try the whole group again.
            continue

        for identity in entry['members']:
            try:
                ccnet_api.group_add_member(group_id, owner, identity)
                done['add'] += 1
            except Exception as exc:
                errors.append('add %s to %s: %s' % (identity, group_id, exc))

    for entry in plan.rename:
        try:
            ccnet_api.set_group_name(entry['group_id'], entry['name'])
            SSOGroupMap.objects.filter(group_id=entry['group_id']).update(
                name=entry['name'])
            done['rename'] += 1
        except Exception as exc:
            errors.append('rename %s: %s' % (entry['group_id'], exc))

    for entry in plan.add:
        try:
            ccnet_api.group_add_member(entry['group_id'], owner,
                                       entry['identity'])
            done['add'] += 1
        except Exception as exc:
            errors.append('add %s to %s: %s'
                          % (entry['identity'], entry['group_id'], exc))

    for entry in plan.remove:
        try:
            ccnet_api.group_remove_member(entry['group_id'], owner,
                                          entry['identity'])
            # Upstream pairs every group removal with this call. Skipping it
            # leaves libraries the departing member shared into the group still
            # attributed to them, so the group keeps data its members can no
            # longer see listed under an owner who is no longer in it.
            seafile_api.remove_group_repos_by_owner(entry['group_id'],
                                                    entry['identity'])
            done['remove'] += 1
        except Exception as exc:
            errors.append('remove %s from %s: %s'
                          % (entry['identity'], entry['group_id'], exc))

    for entry in plan.unmap:
        # The group itself is left alone -- it may own libraries and be shared
        # into. Only the mapping goes, so the sync stops touching it.
        SSOGroupMap.objects.unmap(PROVIDER, entry['external_id'])
        done['unmap'] += 1

    return done, errors


# -- entry points ----------------------------------------------------------

def build_plan(source):
    """Compute the plan without applying it. Used by the dry-run endpoint."""
    raw = source.groups()
    revision = None
    if isinstance(raw, dict):
        # The hierarchical contract wraps the list in {'revision', 'groups'};
        # a bare list is the previous shape and still valid.
        revision = snapshot.revision_of(raw)
        raw = raw.get('groups')
    snapshot_validated = snapshot.validate(raw)
    resolved, unresolved, quarantined = _resolve_members(snapshot_validated)

    mapped = SSOGroupMap.objects.as_dict(PROVIDER)
    members, protected, stale = _current_state(mapped)
    for external_id in stale:
        mapped.pop(external_id, None)

    plan = reconcile.build(resolved, mapped, members, protected=protected,
                           max_removal_ratio=max_removal_ratio(),
                           quarantined=quarantined)
    return plan, {'unresolved': unresolved, 'stale_mappings': stale,
                  'quarantined_groups': sorted(quarantined),
                  'revision': revision}


def sync(registry=None):
    """Reconcile Seafile groups with the directory. Called by cf-worker.

    Never raises: it runs on a schedule, and a task that raises on a
    misconfiguration would just log the same traceback every interval. The
    outcome lands in cf_sso_sync_state, which is what the admin endpoint and
    the capability gate both read.
    """
    from cloudfile_ext.registry import registry as default_registry

    source = directory.active(registry or default_registry)
    if source is None:
        # CF_ENABLE_SSO with no directory selected is a legitimate deployment:
        # upstream's OAuth/SAML login, no group mapping.
        return _record(STATUS_SKIPPED, 'no CF_PROVIDER_SSO_DIRECTORY selected')

    try:
        owner = group_owner()
        plan, notes = build_plan(source)
    except (SyncNotConfigured, directory.DirectoryError,
            snapshot.SnapshotRejected) as exc:
        return _record(STATUS_ERROR, str(exc))
    except reconcile.SyncRefused as exc:
        # Not an error in the plumbing -- a guard doing its job. Distinguished
        # from 'error' so an operator can tell "the feed is broken" from "the
        # feed is fine and I need to raise the ceiling".
        return _record(STATUS_REFUSED, str(exc))
    except Exception as exc:
        logger.exception('SSO directory sync failed')
        return _record(STATUS_ERROR, repr(exc))

    revision = notes.get('revision')
    if revision and plan.empty:
        state = SSOSyncState.objects.get_state(SYNC_TASK)
        if state is not None and state.status == STATUS_OK \
                and _last_revision(state.detail) == revision:
            # Same revision, same clean state: nothing to do. The skip is
            # recorded so operators can see the sync is alive, not stuck.
            return _record(STATUS_SKIPPED, 'revision %s already applied' % revision)

    done, errors = _apply(plan, owner)
    detail = {'applied': done, 'planned': plan.counts()}
    detail.update(notes)
    if errors:
        detail['errors'] = errors[:20]
    status = STATUS_ERROR if errors else STATUS_OK
    return _record(status, _describe(detail))
def sync_user(username, registry=None):
    """Refresh one user's memberships, on login.

    Cheap freshness for the case people actually notice -- somebody added to a
    team this morning wants their libraries now, not at the next tick. It is an
    optimisation on top of the full sync, never a replacement: it can only add
    a user to groups that already exist, because creating a group from one
    member's view of the directory would build it half-populated.
    """
    from cloudfile_ext.registry import registry as default_registry
    from seaserv import ccnet_api

    source = directory.active(registry or default_registry)
    if source is None:
        return None

    try:
        external_ids = source.groups_for_user(username)
    except Exception as exc:
        logger.info('per-user directory lookup for %s failed: %s', username, exc)
        return None
    if external_ids is None:
        return None

    try:
        identity = resolve_user(username)
        owner = group_owner()
    except (UnknownSubject, SyncNotConfigured) as exc:
        logger.info('per-user sync for %s skipped: %s', username, exc)
        return None

    mapped = SSOGroupMap.objects.as_dict(PROVIDER)
    wanted = {eid for eid in external_ids if eid in mapped}
    changed = 0

    for external_id, row in mapped.items():
        group_id = row['group_id']
        try:
            members = {m.user_name for m in ccnet_api.get_group_members(group_id)}
        except Exception as exc:
            logger.info('reading group %s failed: %s', group_id, exc)
            continue

        if external_id in wanted and identity not in members:
            try:
                ccnet_api.group_add_member(group_id, owner, identity)
                changed += 1
            except Exception as exc:
                logger.info('adding %s to %s failed: %s', identity, group_id, exc)
        elif external_id not in wanted and identity in members:
            # Removal matters more than addition here: somebody who left a
            # team keeps their access until the next tick otherwise, and that
            # is the direction where being slow is a security problem rather
            # than an inconvenience.
            try:
                ccnet_api.group_remove_member(group_id, owner, identity)
                changed += 1
            except Exception as exc:
                logger.info('removing %s from %s failed: %s',
                            identity, group_id, exc)

    return changed


def _record(status, detail):
    try:
        SSOSyncState.objects.record(SYNC_TASK, status, detail)
    except Exception:
        # The table is created by cloudfile.sql on start; if it is missing,
        # saying so once is more useful than losing the sync result too.
        logger.exception('could not record SSO sync state')
    logger.info('SSO directory sync: %s %s', status, detail)
    return {'status': status, 'detail': detail}


def _last_revision(detail):
    """Pull the applied revision back out of a recorded detail JSON blob."""
    import json
    try:
        payload = json.loads(detail) if detail else {}
        return payload.get('revision') if isinstance(payload, dict) else None
    except ValueError:
        return None


def _describe(detail):
    import json
    return json.dumps(detail, sort_keys=True)
