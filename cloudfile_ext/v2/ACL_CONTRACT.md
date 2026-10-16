# CF-ACL V1: Hub and Native File Services

This contract uses only `cf_dir_acl`, native library permissions, and verified
current subjects. `acl_policy.resolve` is the single policy algorithm. C and Go
submit actual paths and authenticated actors to Hub; neither implements another
permission precedence algorithm. OAuth2/OIDC and the navigation entry point do
not alter policy.

## Navigation And Eligibility

- Native library r/rw supplies eligibility with `/` as the navigation root.
- Without library eligibility, a matching positive r/rw row **and** `share_mode=1`
  supplies eligibility at that directory. `qualified_root` / `root_path` is that
  directory; ancestors and siblings are inaccessible. Inheritance controls
  descendants; none/invisible still deny. An ordinary positive row without
  sharing does not create library eligibility.
- This is a directory-backed virtual **view**, not a CE `VirtualRepo`, new library,
  object copy, permission copy, or whole-library grant.
- File content uses the containing directory's permission. User > org > role;
  depth, inheritance and same-level conflict behavior are defined by the existing
  policy module. Hard repository read-only and inactive/unready users deny writes.
- Native CE virtual repositories require an origin mapping and remain closed in
  this first integration. They are distinct from the shared-root view.

## SQL And Rule Management

`ACLStore` reads candidate ancestor hashes and current subject keys, validates
stored paths/hashes/revisions, and limits candidate results to 4096. Sharing uses
the existing `acl_shared_subject` index. No new tables or legacy migrations.

The internal writer uses the natural row key
`(repo_id,path_hash,subject_type,provider,namespace,external_id)`.
`expected=None` creates; otherwise it compares the current revision. A fresh UUID
`revision` is the retry key: the same row and revision replay successfully;
conflicting content or a stale expected revision fails. Deletes require the
existing revision. Each transaction locks native `Branch(master)` **before** the
ACL row. Native final commit takes the same Branch lock before consulting Hub.
All writers must use this protocol; direct SQL bypasses its concurrency guarantee.
Permission decisions may remain valid until their bounded cache expiry.

Authenticated administrator GET:
`api/v2.1/cloudfile/authorization/v1/directory-rules/?repo_id=...&path=...`.
Public POST/PUT/DELETE return `503 ACL_PUBLICATION_BLOCKED`, even for staff.
There is deliberately no setting that unlocks publication. Scoped publisher
credentials and the release acceptance gate remain integration work; rw never
implies rule-management authority. The internal CAS writer is not a browser API.

## Content API

Under `api/v2.1/cloudfile/authorization/v1/`:

- `effective-permission/?repo_id=...&path=...&kind=dir|file`
- `shared-directories/` — current subject's eligible existing roots only.
- `directory-entries/?repo_id=...&path=...&offset=0&limit=50` — at most 100 native
  candidates per page, filtered by the same authority. An empty page may have a
  next offset when candidates were hidden. `root_path` is the navigation boundary.

All require a native session/token, use its username, reject subject overrides,
and return `Cache-Control: no-store`. These are content checks, not management
checks. Native file `check-access` also uses this authority for protected repos,
so directory-only access does not fail a preliminary whole-library permission
check. Repo API tokens cannot impersonate current users on protected repos.
Whether a repo is protected is answered from the same library rule snapshot
(a virtual repo also checks its origin; an over-budget library is protected).

## Native Decision Protocol

`POST api/v2.1/internal/cloudfile/acl/check/`, using the existing internal HS256
JWT: `is_internal=true`, required expiry, at most 310 seconds into the future.
Body:

```json
{"username":"native-user","repo_id":"canonical-uuid","checks":[{"path":"/shared/file","kind":"file","action":"write"}]}
```

1–4096 canonical paths. The caller derives username from its authenticated
request/access token, never a commit author or client principal claims. A grant
is exactly HTTP 200 with `{"allowed":true,"contract":"cf-acl-v1"}`. Redirects, missing fields, invalid identities and authority failures do not grant
access. A valid bounded cached policy decision is allowed; an old access ticket
alone is not a policy decision. The native client bounds response size and time.

`CF_ACL_PROVIDER` and the server-configured dotted callable
`CF_ACL_SUBJECT_ENSURE(uid, username)` are the subject integration seam. The latter
must call the existing Memberships TTL projector successfully; failure raises.
Only then does Hub read `cf_sso_group_map JOIN GroupUser`. Missing adapter means
503, never stale-group fallback. This package does not claim package A is wired.

## Revocation And Efficiency

Rules are sparse compared with library files, so Hub caches **all rows of one
library** in Seahub's configured Django cache and evaluates every user, directory
and final-commit path in process. `CF_ACL_CACHE_TTL` defaults to 180 seconds;
0 disables cross-request caching, and the maximum is 300 seconds. Expiry starts at
the SQL read and is also stored in the value. A library over 4096 rows caches only
that marker and falls back to per-directory candidate reads.

Within one request the library rows are read once (also with TTL=0) and filtered
to the current verified subject; directory decisions, native library permission
and hard-readonly status are memoized only for that request. Native library grants
and current subjects are never cached across requests by this layer.

A committed `ACLStore` write switches the library's cache namespace
(`cf-acl-rules-v1:gen:<repo>`, a cache key, not a table), so later checks read
fresh rows; an older in-flight reader can only refill the abandoned namespace.
Direct SQL edits, or a failed namespace switch, take effect within the TTL.
Cache failure recomputes from SQL; SQL failure fails closed and is never cached.
External group changes retain the existing subject TTL. Final Commit binds the
actual actor and diff paths and may use the cached library rows. Strict-mode tests
set TTL=0.

## Native Scope And Release Status

Both native processes read `[cloudfile] v2_acl_enabled=true`; default is off.
Do not enable public rule publication merely because these hooks are configured.

The first supported seam is current-path read/Range and fresh byte uploads /
overwrites, with actual final-diff checks under Branch CAS. C trusted post/put
file calls carry the actor explicitly. Unscoped commits never infer it from commit
metadata. Object-only tickets, native sync and public links on protected repos
remain closed. Native copy/move is closed **throughout ACL mode** until both
source and destination can be proven transactionally; checking an initially
unprotected source is insufficient. Other structural operations on protected
repos remain closed until lifecycle/source/destination checks are implemented.
CF-EDIT remains an independent constraint and provides no ACL grants.

The integrator must retain publication blocking until the real subject adapter,
scoped management credentials, all exposed read/write routes, lifecycle behavior,
and deployment acceptance are complete. This minimal seam is not full ACL release
certification. Internal test adapters are not production authentication.
