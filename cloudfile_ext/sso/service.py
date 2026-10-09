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
from cloudfile_ext.sso.identity_bridge import IdentityBridgeError, resolve_eap_pairs, load_login_identities
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


def external_group_id(external_id):
    """Resolve a directory external id to its Seafile group id, or None.

    Consumed by directory ACL as the group-map resolver installed at startup:
    when SSO is on, a dept/group subject typed as an external id is translated
    before the native group-id check. Returns None when the id is not mapped,
    which lets the caller fall back to treating it as a Seafile group id --
    both shapes exist in the wild (departments were written by external id,
    roles by Seafile group id), so refusing either would break live rules.

    Reads the whole map on each call. That is fine here: rule writes are
    infrequent admin operations, not a hot path.
    """
    try:
        row = SSOGroupMap.objects.as_dict(PROVIDER).get(external_id)
    except Exception:
        logger.exception('group-map lookup failed for %s', external_id)
        return None
    return row['group_id'] if row else None


def group_external_id(group_id):
    """Resolve a Seafile group id back to its directory external id, or None.

    The reverse of :func:`external_group_id`, consumed by directory ACL's read
    path (``_external_subject_id``) so a stored dept/group subject -- which
    enforcement compares as a Seafile group id -- is shown to the external
    system as the id its own directory knows (``583 -> '7'``).

    ``SSOGroupMap.group_id`` is unique, so at most one external id answers.
    A group id with no mapping (a hand-created Seafile group, or a role group
    whose row was keyed differently) returns None and the caller passes the
    group id through unchanged.
    """
    try:
        row = SSOGroupMap.objects.filter(
            provider=PROVIDER, group_id=group_id).values_list(
            'external_id', flat=True).first()
    except Exception:
        logger.exception('group-id reverse lookup failed for %s', group_id)
        return None
    return row


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

def _resolve_members(entries):
    """Map directory logins onto Seafile identities.

    Current EAP snapshots include member_login_ids (stable employee account_)
    as well as member_user_ids and optional member_accounts (contact emails).
    Resolve the login IDs via the indexed and unique Seahub Profile.login_id
    field. Never silently substitute contact_email for an explicit missing
    login_id: email can be absent, change, or belong to another person.

    Older providers without member_login_ids retain the legacy identity
    resolver and are isolated from this v2 behavior.

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
    # Stable login IDs allow an indexed 256-row lookup in place of one
    # contact-email query per member occurrence (tens of thousands of repeats).
    logins = set()
    pairs = {}
    conflicting_uids = set()
    for entry in entries:
        if snapshot.MEMBER_IDENTITIES in entry:
            for pair in entry[snapshot.MEMBER_IDENTITIES]:
                uid = pair['user_id']
                if uid in pairs and pairs[uid] != pair['employee_no']:
                    conflicting_uids.add(uid)
                pairs[uid] = pair['employee_no']
        elif snapshot.MEMBER_LOGIN_IDS in entry:
            logins.update(v for v in entry[snapshot.MEMBER_LOGIN_IDS]
                          if isinstance(v, str) and v.strip())
    try:
        pair_identities = resolve_eap_pairs(
            [{'user_id': uid, 'employee_no': employee} for uid, employee in pairs.items()
             if uid not in conflicting_uids]
        ) if pairs else {}
        login_identities = load_login_identities(logins) if logins else {}
    except IdentityBridgeError as exc:
        raise SyncNotConfigured('EAP directory UID/employee identity collision') from exc
    except Exception as exc:
        raise SyncNotConfigured('EAP directory identity mapping unavailable') from exc
    for group in entries:
        members = []
        broken = False
        if snapshot.MEMBER_IDENTITIES in group:
            if group.get('identity_conflict'):
                broken = True
                unresolved.append('%s: conflicting EAP identity records' % group['external_id'])
            for pair in group[snapshot.MEMBER_IDENTITIES]:
                uid = pair['user_id']
                native = pair_identities.get(uid)
                if native is not None:
                    members.append(native)
                else:
                    unresolved.append(uid)
                    broken = True
                # A missing employee number does not prevent an exact UID
                # match, but it must not be treated as a complete revocation
                # snapshot until the directory repairs the employee record.
                if pair['employee_no'] is None:
                    broken = True
            if broken:
                unresolved.append('%s: incomplete business identity' % group['external_id'])
        elif snapshot.MEMBER_LOGIN_IDS in group:
            subjects = [v.strip() for v in group[snapshot.MEMBER_LOGIN_IDS]
                        if isinstance(v, str) and v.strip()]
            expected = {str(v).strip() for v in (group.get('members') or [])}
            # Mismatched cardinality means EAP omitted account_ for a member
            # or reused a login_id. Refuse removals in this group.
            if len(subjects) != len(expected) or len(set(subjects)) != len(subjects):
                broken = True
                unresolved.append('%s: incomplete employee login mapping' % group['external_id'])
            for login in subjects:
                native = login_identities.get(login)
                if native is None:
                    unresolved.append(login)
                    broken = True
                else:
                    members.append(native)
        else:
            # Legacy provider: no explicit business login binding yet.
            accounts = group.get(snapshot.MEMBER_ACCOUNTS)
            subjects = ([str(a).strip() for a in accounts if str(a).strip()]
                        if accounts else group.get('members') or [])
            for login in subjects:
                try:
                    members.append(resolve_user(login))
                except UnknownSubject:
                    unresolved.append(login)
                    broken = True
        entry = dict(group)
        entry['members'] = sorted(set(members))
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
    # The configured technical owner is infrastructure, not a directory employee.
    # Older groups may have another creator; never remove this account on sync.
    technical_owner = group_owner()
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
        protected[group_id] = list({group.creator_name, technical_owner})
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
    incomplete = bool(notes.get('unresolved') or notes.get('quarantined_groups'))
    if revision and plan.empty and not incomplete:
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
    # An incomplete roster must remain retryable and visible even when safe
    # additions succeeded; quarantine protects existing members from removal.
    status = STATUS_ERROR if errors or incomplete else STATUS_OK
    return _record(status, _describe(detail))
def sync_user_id(user_id, *, dry_run=True, registry=None):
    """Incrementally compare exactly ONE EAP UID's direct CE group memberships.

    This requires the authoritative v2 context, both business identity keys,
    all desired EAP groups already mapped, and an explicit operator-controlled
    apply flag. No synchronization of other employees or group creation occurs.
    """
    from django.conf import settings
    from cloudfile_ext.registry import registry as default_registry
    from cloudfile_ext.sso.incremental import IncrementalRefused, plan_uid_delta
    from seaserv import ccnet_api, seafile_api
    if not isinstance(user_id, str) or not user_id.strip() or len(user_id) > 225:
        return {'status': 'refused', 'reason': 'invalid EAP UID'}
    source = directory.active(registry or default_registry)
    if source is None or not hasattr(source, 'context_for_user_id'):
        return {'status': 'refused', 'reason': 'v2 UID provider unavailable'}
    try:
        context = source.context_for_user_id(user_id)
        employee_no = context['attributes'].get('employee_no')
        if employee_no is not None and not isinstance(employee_no, str):
            raise IncrementalRefused('invalid employee number in EAP context')
        native = resolve_eap_pairs([{'user_id': user_id, 'employee_no': None}]).get(user_id)
        if native is None:
            return {'status': 'unmapped', 'reason': 'native CE account not provisioned'}
        native_user = ccnet_api.get_emailuser(native)
        if native_user is None:
            raise IncrementalRefused('native CE identity does not exist')
        mapped = SSOGroupMap.objects.as_dict(PROVIDER)
        # Native get_groups may include ancestor departments. Only direct
        # memberships may be removed; confirm each candidate via members RPC.
        linked = ccnet_api.get_groups(native)
        if linked is None or len(linked) > 4096:
            raise IncrementalRefused('native membership unavailable')
        mapped_gids = {item['group_id'] for item in mapped.values()}
        direct = set()
        for group in linked:
            if group.id not in mapped_gids:
                continue
            row = ccnet_api.get_group(group.id)
            if row is None:
                raise IncrementalRefused('native group disappeared')
            members = ccnet_api.get_group_members(group.id)
            if members is None:
                raise IncrementalRefused('native group members unavailable')
            if any(member.user_name == native for member in members):
                direct.add(group.id)
        configured = getattr(settings, 'CF_SSO_UID_DELTA_MAX_REMOVALS', 0)
        maximum = int(configured)
        # DEV full sync guard=0 also guards per-UID membership removals.
        if max_removal_ratio() == 0:
            maximum = 0
        planned = plan_uid_delta(context, mapped, direct, max_removals=maximum)
        counts = {key: len(value) for key, value in planned.items()}
        if dry_run:
            return {'status': 'planned', 'planned': counts, 'etag': context['etag']}
        if str(getattr(settings, 'CF_SSO_UID_DELTA_APPLY_ENABLED', 'false')).lower() != 'true':
            return {'status': 'refused', 'reason': 'UID delta mutation disabled', 'planned': counts}
        owner = group_owner()
        done = {'add': 0, 'remove': 0}
        errors = []
        for gid in planned['add']:
            try:
                ccnet_api.group_add_member(gid, owner, native)
                done['add'] += 1
            except Exception:
                errors.append('add failed')
        # Do not start removals after a failed add in the same user delta.
        if not errors:
            for gid in planned['remove']:
                try:
                    ccnet_api.group_remove_member(gid, owner, native)
                    seafile_api.remove_group_repos_by_owner(gid, native)
                    done['remove'] += 1
                except Exception:
                    errors.append('remove failed')
        return {'status': 'error' if errors else 'ok', 'planned': counts,
                'applied': done, 'errors': errors}
    except (directory.DirectoryError, IdentityBridgeError, IncrementalRefused,
            SyncNotConfigured, ValueError) as exc:
        # No underlying SQL, JWT, employee name or access token in response.
        logger.info('UID-scoped directory delta refused: %s', exc.__class__.__name__)
        return {'status': 'refused', 'reason': 'directory UID delta unavailable'}
    except Exception:
        logger.exception('UID-scoped directory reconciliation failed')
        return {'status': 'error', 'reason': 'directory UID delta failed'}


def sync_user(username, registry=None):
    """Refresh one user's memberships, on login.

    Cheap freshness for the case people actually notice -- somebody added to a
    team this morning wants their libraries now, not at the next tick. It is an
    optimisation on top of the full sync, never a replacement: it can only add
    a user to groups that already exist, because creating a group from one
    member's view of the directory would build it half-populated.

    Scheme B maps the native identity back to Profile.login_id (EAP UID).
    A v2 provider supplies a complete authenticated context to sync_user_id;
    removals require both the apply switch and explicit removal guards. A
    refusal remains retryable, because falling back to a partial legacy query
    could bypass those guards. Providers without UID contexts retain
    additions-only refresh.

    Returns the number of memberships changed, or ``None`` when the refresh could
    not be attempted at all (no directory selected, identity unresolvable, no
    login account on the profile, or the directory lookup failed).
    **Callers rely on ``None`` vs ``0`` being different**: the login signal in
    ``cloudfile_ext/sso/__init__.py`` only throttles its next run after an
    attempt that actually ran -- a skipped first login (the profile is written
    *after* ``auth.login()`` fires the signal) must not burn the throttle
    window. Keep the two apart if this is ever refactored.
    """
    from cloudfile_ext.registry import registry as default_registry
    from cloudfile_ext.identity import login_of
    from seaserv import ccnet_api

    source = directory.active(registry or default_registry)
    if source is None:
        return None

    try:
        identity = resolve_user(username)
        owner = group_owner()
    except (UnknownSubject, SyncNotConfigured) as exc:
        logger.info('per-user sync for %s skipped: %s', username, exc)
        return None

    # Scheme B stores the authoritative EAP UID in Profile.login_id.
    login_account = login_of(identity)
    if not login_account:
        logger.info('per-user sync for %s skipped: no login account on profile',
                    identity)
        return None

    if hasattr(source, 'context_for_user_id'):
        # Only a complete authenticated UID context may remove stale memberships.
        # A refusal keeps the login refresh retryable and never falls back to
        # an ambiguous legacy empty group response.
        result = sync_user_id(login_account, dry_run=False, registry=registry)
        if result.get('status') == 'ok':
            return sum(result['applied'].values())
        return None

    try:
        external_ids = source.groups_for_user(login_account)
    except Exception as exc:
        logger.info('per-user directory lookup for %s failed: %s', username, exc)
        return None
    if not external_ids:
        # None ("this source cannot say") and [] ("says nothing useful") both
        # mean: do nothing. Neither is evidence that membership should shrink.
        return None

    mapped = SSOGroupMap.objects.as_dict(PROVIDER)
    wanted = {eid for eid in external_ids if eid in mapped}
    changed = 0

    for external_id, row in mapped.items():
        if external_id not in wanted:
            continue
        group_id = row['group_id']
        try:
            members = {m.user_name for m in ccnet_api.get_group_members(group_id)}
        except Exception as exc:
            logger.info('reading group %s failed: %s', group_id, exc)
            continue

        if identity not in members:
            try:
                ccnet_api.group_add_member(group_id, owner, identity)
                changed += 1
            except Exception as exc:
                logger.info('adding %s to %s failed: %s', identity, group_id, exc)

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
    # One employee can occur in many ancestor groups. Persist bounded samples
    # and exact totals, not tens of thousands of repeated IDs on every tick.
    summary = dict(detail)
    for key in ('unresolved', 'quarantined_groups'):
        if isinstance(summary.get(key), list):
            values = summary[key]
            unique = sorted(set(values))
            summary[key + '_count'] = len(values)
            summary[key + '_unique_count'] = len(unique)
            summary[key] = unique[:20]
    return json.dumps(summary, sort_keys=True)
