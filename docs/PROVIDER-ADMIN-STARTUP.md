# Enterprise administrator sync: one check at startup

**Development contract, not yet released.**

CloudFile uses Seafile CE's native administrator mechanism. The local native
`cfadmin` account remains independent. A trusted enterprise Directory may
declare a *small and infrequently changing* set of external superadmins; those
users continue to authenticate through the configured enterprise SSO/OIDC
login, not a separate CloudFile-specific admin login.

This replaces the abandoned proposal to query the Directory on every
administrator HTTP request, Session, API Token or routine GroupUser refresh.

## One source, one bounded startup operation

When `CF_PROVIDER_ADMIN_STARTUP_SYNC_ENABLED=true`, Docker invokes
`manage.py cf_sync_provider_admins` **once after Seafile and Seahub start**.
It is not a Django `AppConfig.ready()` side effect, Gunicorn worker hook,
cron job or per-request API call.

The command obtains one full, machine-authenticated Provider snapshot.
The default built-in enterprise adapter calls the configured Directory endpoint
`GET /administrators`, reusing the existing scoped short-lived machine JWT.
Other enterprise deployments can set `CF_PROVIDER_ADMIN_SOURCE` to a
server-configured Python callable that returns the identical contract.

Example (illustrative, no credentials):

```json
{
  "contract_version": "1.0",
  "complete": true,
  "generated_at": "2026-10-24T12:00:00Z",
  "admins": [
    {"uid": "stable-user-42", "account": "companyadmin"}
  ]
}
```

The snapshot is rejected if it does not assert `contract_version: "1.0"` and
`complete: true`, if `generated_at` is missing, timezone-naive or outside a
±60 second window, or if the `admins` list is malformed, duplicated,
unexpectedly empty or larger than 32 administrators. A failed call **does
not** mean that there are zero administrators, and none of these rejections
writes CE admin state.

`complete: true` is the Provider's own assertion, not a fact CloudFile can
recompute. A list the Provider truncates while still setting `complete: true`
cannot be distinguished locally, which is why enabling this feature is a trust
decision in the Provider and in the channel that carries its response.

CloudFile resolves each UID to its existing native CE User/Profile or
pre-creates an active non-staff account with an unguessable password through
the native CE RPC. The *complete* desired set is then reconciled in a single
MySQL transaction against the CE `EmailUser.is_staff` and Seahub
`role_permissions_adminrole.role=default_admin`. It grants newly listed
users, preserves unchanged users and removes absent `default_admin` entries **only if** explicitly identified in the configured managed-account scope.

**No new permission table, managed-library concept, background task, or
special administrator revocation service.** Normal usage reads CE native
permissions exactly as before.

## Account ownership / safety boundaries

- This mode reserves **explicit `default_admin`** for the enterprise
  Provider's administrator projection, among users with verified stable
  `Profile.login_id`. Existing native `cfadmin` and independent
  `system_admin` assignments are untouched.
- **Before the first enablement**, review any native manually assigned
  `default_admin` and migrate them appropriately; without a second
  provenance table, two identical role rows cannot otherwise be distinguished.
- Ordinary Org/Role groups, display name, mailbox or `account='admin'`
  seen in browser requests do not grant superadmin: only the complete,
  machine-authenticated Provider list can change the native role.
- Provider-only admin accounts need the enterprise SSO login path. Account
  pre-creation uses a random, noninteractive native password; operators must
  ensure external administrators are not granted a separate usable native
  password or long-lived application tokens that bypass the SSO policy.
- CloudFile does **not** repeatedly check Provider administrator membership.
  A grant is added on the **next successful startup sync** (or one manual
  invocation of the same command). A **removal is only applied when the
  affected CE username is listed in `CF_PROVIDER_ADMIN_MANAGED_ACCOUNTS`**;
  with the default empty scope, an account the Provider no longer lists keeps
  its CE `default_admin` role until an administrator removes it natively or
  adds it to the managed scope. Stale `default_admin` rows are therefore
  retained indefinitely by default, so operators must audit them and keep the
  managed scope current. Existing browser sessions may remain active until
  normal SSO/CE expiry; urgent departures need IdP/session intervention and an
  immediate controlled sync or restart.
- If the Provider is unavailable at boot, the sync logs FAILED, and the
  existing native administrator state is retained. CloudFile itself still
  starts; `cfadmin` remains a recovery account. There is **no automatic
  retry loop**. The administrator can rerun the same command after fixing
  the Directory.

## Configuration

`CF_PROVIDER_ADMIN_STARTUP_SYNC_ENABLED=false` by default in generic
Standalone deployments; after verifying the Provider endpoint and reviewing
existing administrators, the operator can set it to `true` and restart
CloudFile. The existing enterprise Directory URL/key/secret are reused.
`CF_PROVIDER_ADMIN_SOURCE` is optional for non-default Provider adapters.

These four names are Django settings written to `conf/seahub_settings.py`; the
compose deployment generates them from environment variables of the same name.
`CF_PROVIDER_ADMIN_STARTUP_SYNC_ENABLED` must become boolean `True` (a
hand-written settings file containing the string `"true"` leaves the sync
disabled, not enabled). `CF_PROVIDER_ADMIN_SOURCE`, when used, must be a
server-side Python dotted path and never a value derived from a request or from
ordinary user input. `CF_DIRECTORY_URL` must be an `https://` URL: the
Directory adapter also accepts plain `http://`, which is not acceptable for a
channel that can grant CE superadmin.

Manual one-off invocation is the same management command:

```bash
/opt/seafile/seafile-server-latest/seahub.sh python-env \
  python3 /opt/seafile/seafile-server-latest/seahub/manage.py cf_sync_provider_admins
```

Use the actual installation version or symlink provided by the image.
Running this command does not change the setting, add an HTTP endpoint
or start a daemon.

## Minimal acceptance before enabling

1. Fresh complete admin list under machine JWT; invalid/empty/time-out list
   causes **no** CE admin mutations, and CloudFile can still start.
2. Fixed UID/account → CE Profile binding, no mailbox merge, no arbitrary
   manual admin adoption, native `cfadmin` remains unaffected.
3. First startup grant, second startup idempotent, changed list revoke/grant,
   readback, failed cross-schema write rollback, and multiple-container lock.
4. Real SSO login with enterprise administrator, expected CE admin UI/API,
   ordinary user not elevated; failure of enterprise SSO does not affect
   independent native `cfadmin`.
5. Document the operator's accepted change delay and normal SSO/session
   lifetime. Do not claim immediate revocation before another successful
   startup sync.

Routine PR CI is not a substitute for real CE/MySQL/EAP DEV checks.

## Explicit ownership for safe removal

By default, the roster sync **does not revoke existing** `default_admin` users absent from a provider snapshot. To revoke a previously provisioned account automatically, the operator must include its exact CE username in `CF_PROVIDER_ADMIN_MANAGED_ACCOUNTS` (comma-separated). This optional bounded list is an explicit operator declaration of ownership, not a new source-of-truth table. Never add unrelated CE administrators to this list. The scope itself is
validated before any CE account is created: at most 32 unique, non-empty CE
usernames, none of them `cfadmin`, and an invalid scope aborts the whole sync
with no writes. Matching is against the exact stored native username, so a typo
means "no revocation" rather than a broader removal. Normal new grants and unchanged roles remain idempotent. When changing a Provider admin roster, update the managed account list and re-run the same command, or use existing CE native administration for urgent removal. In particular, `cfadmin` stays independent. No per-request check is added.

### Optional deployment administrator compatibility

`CF_PROVIDER_ADMIN_EXPECTED_ACCOUNT` defaults to empty. An enterprise deployment can set it to its known business administrator account (enterprise Directory example: `admin`). The **trusted complete machine-authenticated roster must contain that exact account**, otherwise startup synchronization fails without role changes. This is a compatibility/health assertion, **not** an alternate elevation mechanism: username alone never grants CE rights; the normal UID, native Profile and IdP SSO rules still apply. Built-in `cfadmin` remains independent. No runtime Provider checking is introduced.
