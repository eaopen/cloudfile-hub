# Enterprise Directory facts (CloudFile Hub #54)

This document describes the small trust-boundary helpers in
`cloudfile_ext/v2/provider_contract.py`. This is **not** a new Directory
microservice, credential format, database layer or authorization engine.

## Independence

- CE standalone: no enterprise Directory is required. CE native accounts and
  sessions work as before.
- Authn/SSO (OIDC or existing OAuth2) proves a login. A server-selected
  enterprise Directory, when configured, separately supplies authoritative
  user/organization/role facts for existing CE projection.
- No account name, email, Org label or role name grants administrator or file
  permissions by itself.
- UID is the long-lived authorization identity. Account names are optional,
  trusted **creation metadata**; an existing exact UID/Profile binding wins
  even if a later account label changes.
- The only persisted mappings remain CE User/Profile, native Group/GroupUser
  and the already established `cf_sso_group_map`.

## Minimal trusted Provider interface

A provider adapter is a server-configured callable, not a dynamically
installed plugin. It supplies two kinds of data:

1. A current UID-scoped user context, comprising `userId`, active/disabled
   `status`, bounded `generated_at`, opaque `etag`, `attributes`, and
   `organizations`, `roles`, `organization_ancestors` collections.
   `verified_user(context, uid, account_field='account')` checks the exact
   UID, freshness, duplicates and active state, then returns the optional
   display/login label and creation account. No CE writes occur here.
   `direct_memberships(context, uid)` returns only directly assigned Org/Role
   keys; ancestor facts are validated but never converted into membership by
   this helper. No CE GroupUser writes occur.
2. A bounded `{contract_version:'2.0', view:'entities', generated_at, groups}`
   snapshot containing `subject_type` (org/role), `namespace`,
   `external_id`, `name`, optional `parent_external_id`.
   `validated_entities` returns `(kind, namespace, id) -> name`.
   Conflicting, stale, malformed, duplicate and invalid parent values reject
   the entire response. Namespaces are provider facts and do not merge on
   display name.

Existing enterprise Directory wiring continues to use the machine-authenticated
`/users/{uid}/context` and `/groups?view=entities` endpoints. enterprise Directory maps
`attributes.employee_no` to its account, keeps namespace pairs
`(org,directory)` and `(role,role)`, and uses its existing
`cf_sso_group_map` / user TTL projection. A generic provider can use other
namespace pairs, but must explicitly implement the trusted refresh callback
described in #61. This PR does **not** create generic network routing.

## Important boundaries and deferred work

- A provider supplies facts, **never** executable file permissions.
- Native GroupUser projection continues under the existing Hub runtime.
- A parent Org field is checked as data, not automatically converted into
  inherited CE membership. The default direct-Org / orgLevel behavior is
  managed separately in Draft #63; do not infer that merging this parser
  alone changes the currently deployed ancestor behavior.
- The full hierarchy validation and depth rules (0/1/N) belong to #55.
- Admin startup roster synchronization remains isolated under #64.
- Runtime CE/enterprise Directory login, GroupUser refresh and MariaDB validation remain a
  separate DEV acceptance gate. Fast Python tests prove only parsing logic.

Aim: a provider-neutral, tiny contract compatible with the existing enterprise Directory
adapter, without inventing a framework or adding cf_* tables.

## Runtime organization/role synchronization (2026-10-25)

- Configured enterprise Directory: existing `cf_worker` registers
  `directory-entities` every `CF_DIRECTORY_SYNC_INTERVAL_SECONDS` seconds,
  default 600 (10 minutes, supported 60–86400). The worker must be running.
- Periodic sync reconciles organization/role mappings and names, not users
  or individual GroupUser memberships. Unchanged groups are read in one
  snapshot rather than each acquiring a lock and native RPC.
- OAuth login refreshes the authenticated existing user's memberships.
  Missing role/org mapping refuses the refresh. Neither login nor an
  ACL check automatically creates a missing group; scheduled or explicit
  directory synchronization owns catalog creation.
- On file permission checks the built-in principal reads only existing
  CE User/Profile/GroupUser/cf_sso_group_map facts. No external HTTP
  Directory fetch, JIT user provision, group creation or membership mutation.
  A missing native user is denied.
- A user's changed membership is refreshed at the next authenticated login
  or explicit administrative user-sync event, **not** on each ACL request.
  The ten-minute org/role catalog cadence is not a guarantee of ten-minute
  active-user membership revocation.
- Internal native **write** permission checks load current ACL rows without
  cross-request TTL caching while reusing results within the request;
  read/list permission checks keep bounded shared library caching.
- Custom `CF_ACL_SUBJECT_ENSURE` adapters must be read-only. The old
  built-in value `cloudfile_ext.v2.directory_adapter.ensure_subject`
  remains accepted but no longer triggers synchronization in ACL reads.

No new CloudFile tables, queue, permission database or scheduler service.
