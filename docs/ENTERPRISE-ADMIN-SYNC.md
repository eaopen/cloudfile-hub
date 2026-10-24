# Enterprise administrator synchronization — engineering rollout contract

**State: Draft implementation, disabled by default. Not a release instruction.**

CloudFile enterprise Directory is optional. Native CE users and the built-in `cfadmin`
remain independently managed. An enterprise Provider can assert an administrator
fact for a verified `uid`, but ordinary Org/Role memberships must **not** grant
CE system administrator authority.

## Facts and supported path

- The server-configured, machine-authenticated Directory returns an exact
  `userId`, `status`, short-lived `generated_at` and boolean
  `super_admin`. The standard Etech Directory adapter verifies the complete
  current-user snapshot; third-party adapters must supply equivalent freshness
  and integrity checks before being eligible for administrator sync.
- `super_admin=true` maps to CE `EmailUser.is_staff=1` **and** Seahub
  `role_permissions_adminrole.role=default_admin`. Neither a user-provided
  name, an OAuth UserInfo `role`, a directory group name, nor a browser flag
  is administrator proof.
- `super_admin=false` on an active provider-managed account revokes the
  persisted Staff/AdminRole on its next trusted preprovision or verified OIDC
  login. Disabled accounts are denied privileged requests immediately;
  persistent cleanup for disabled users is **not yet automatic**.
- A server-side Session and both CE API Token paths validate current Provider
  authority on privileged administrator accounts on **every request**, without
  using the regular user GroupUser TTL as an admin-role cache.
- For a source failure, revoked/missing/malformed claim or disabled principal,
  the in-memory staff/admin role is masked for that request. Ordinary CE file
  access still follows its own ACL; there is no fallback to stale Staff bits.
- Exact built-in native `cfadmin` remains independent of the external
  Directory. A CE-only setup does not require enterprise authentication.

## Configuration boundaries (do not enable in a running environment yet)

- `CF_PROVIDER_ADMIN_SYNC_ENABLED`: **unset / False by default**. When
  explicitly set True, eligible trusted login and preprovision paths may
  reconcile CE Staff and AdminRole; the request-time gate also activates.
- `CF_PROVIDER_ADMIN_GUARD_ENABLED`: **unset / False by default**. Setting
  this True enforces fresh Provider admin authority on browser Sessions and
  API Tokens even while `SYNC_ENABLED=False` (no new native admin grants).
  This is the required **guard-only rollback mode** until persisted
  provider-managed Staff/AdminRole rows have been safely cleared.
- `CF_DIRECTORY_URL` and its machine-credential settings: choose the
  existing built-in trusted enterprise Directory adapter.
- `CF_PROVIDER_ADMIN_SUBJECT_FETCH`: optional fully qualified **server-side**
  callable for another enterprise Provider. The callback must itself verify
  fresh authenticated Directory facts. Never point it at caller-provided data.
- Do not enable the flag until the Directory returns `super_admin` explicitly,
  all stacked PRs have been reviewed and merged in order, CE accounts have
  been audited, and E2E Sessions/API Tokens/admin APIs have passed on DEV.
- Under the five-table V2 baseline there is no separate durable per-user
  administrator-provenance table. Opting in designates the configured external
  identity namespace as the **exclusive authority** for its CloudFile
  administrator privileges. Review pre-existing native `default_admin`
  assignments in that namespace first; independent native administrators
  and `cfadmin` remain outside the projector.

## Critical operations / rollback warning

**DO NOT disable both `CF_PROVIDER_ADMIN_SYNC_ENABLED` and
`CF_PROVIDER_ADMIN_GUARD_ENABLED` while any enterprise administrator remains
materialized.** Otherwise an old Session/API Token could exploit residual
`EmailUser.is_staff=1` with no fresh Provider proof. Safe rollback is:

1. Disable new grants but **keep read enforcement**:
   `CF_PROVIDER_ADMIN_SYNC_ENABLED=False`,
   `CF_PROVIDER_ADMIN_GUARD_ENABLED=True`. Provider revocations and outages
   continue to deny privileged requests even though native Staff may remain.
2. Using an independently authenticated native `cfadmin`, reconcile/demote
   *every external managed administrator*, verify CE Staff and AdminRole
   readbacks, and revoke old Session/API Tokens as needed. Protect
   independent native accounts.
3. Only **after** all external managed Staff records are cleared or
   otherwise explicitly reviewed and de-scoped, disable the guard if
   desired. Losing the Directory alone is never a reason to grant fallback
   system administrator access.

A separate guarded deprovision/rollback procedure and DEV test are **release
blockers**, not optional enhancements.

## Engineering acceptance still required

- Fixed CE14 Hub/Server/Docker SHAs and actual image Digest;
- MySQL transaction, native CE RPC identity freshness and Role readback;
- exact UID and OAuth issuer/sub pairing, shared email, deleted/disabled users;
- administrator delegation, all native admin UI/API entrypoints, browser
  Sessions, Token V1/V2 and legacy/cross-protocol authentication;
- request-time Provider timeout / revoke / token replay;
- operator adoption audit of existing Staff/AdminRole and complete rollback;
- callback contract for a non-Etech Directory Provider.

Only targeted source/contract tests are automated by the current PR branches.
Their passing does **not** constitute production-readiness.
