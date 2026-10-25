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
  inherited CE membership. Hub #63 has merged direct-Org membership as the
  default; deployment acceptance must still confirm real enterprise groups.
- The full hierarchy validation and depth rules (0/1/N) belong to #55.
- Admin startup roster synchronization is implemented but remains opt-in;
  it is independent of ordinary ACL and Directory lookups (Hub #71 / #64).
- Runtime CE/enterprise Directory login, GroupUser refresh and MariaDB validation remain a
  separate DEV acceptance gate. Fast Python tests prove only parsing logic.

Aim: a provider-neutral, tiny contract compatible with the existing enterprise Directory
adapter, without inventing a framework or adding cf_* tables.

## External organization/role synchronization (2026-10-25)

- **Stable provider namespace for existing permissions.** A machine-authenticated
  `/groups?view=entities` response may include `provider` (Etech uses `etech`).
  CloudFile uses an explicit `CF_DIRECTORY_PROVIDER` / `CF_ACL_PROVIDER` first,
  otherwise one validated Directory declaration per Hub worker,
  otherwise the generic `external` default. The first lookup is one bounded
  machine-authenticated request; concurrent cold calls share the result. On
  failure, return unavailable (503) and retry after a fixed 30-second in-process
  cooldown instead of hammering EAP. Valid declarations and old responses with
  no declaration are pinned for the worker lifetime. Upgrade EAP first, then
  restart Hub to pick up a newly declared namespace. Explicitly configured
  namespaces never change, and no ACL/group rows are migrated.
- **Etech owns the business Directory and schedules catalog updates.** Its existing
  PowerJob `cloudDirectorySync` calls the CloudFile administrator endpoint
  `POST /api/v2.1/admin/cloudfile/directory/entities/sync/`. Other enterprise
  integrations may use their own scheduler. CloudFile never schedules recurring
  org/role fetches by itself; there is no interval/mode parameter.
- The Hub endpoint fetches `GET /groups?view=entities` from the trusted
  enterprise Directory using the existing machine JWT, validates the snapshot
  and reconciles only organization/role mappings and native Group names.
  It does **not** bulk-create users or write GroupUser memberships.
- A standalone CE/CloudFile installation without an external Directory needs
  no organizational synchronization or CloudFile background scheduler.
- OAuth login refreshes only the authenticated existing user's memberships.
  Missing role/org mapping refuses the refresh. Neither login nor an
  ACL check automatically creates a missing group; external application
  catalog synchronization owns creation and retry.
- Warm file permission checks use only existing CE User/Profile/GroupUser and
  `cf_sso_group_map` facts. Namespace discovery can make **one initial** trusted
  Directory request per Hub worker when there is no explicit namespace; after
  that, ACL checks do no external HTTP, user/group provisioning or membership
  mutation. A missing native user is denied.
- A user's changed membership is refreshed at their next authenticated login
  or explicit administrative user-sync event, **not** at every ACL request.
  The external catalog schedule does not guarantee prompt revocation of
  active-user memberships.
- Internal native **write** permission checks load current ACL rules without
  cross-request TTL caching while reusing results within one request; reads
  retain bounded shared caching.
- Custom `CF_ACL_SUBJECT_ENSURE` adapters must be read-only. The built-in
  `cloudfile_ext.v2.directory_adapter.ensure_subject` value remains
  recognized but does not trigger synchronization in ACL reads.

CloudFile owns native mapping and authorization; Etech owns the source facts
and the trigger. No new task tables, schedule modes, or polling services.
