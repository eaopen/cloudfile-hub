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
  descendants; the only explicit deny value is `invisible` (hidden and unreadable). An ordinary positive row without
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

`path_hash` is `BINARY(32)`, the SHA-256 of the canonical path, and that is the
only accepted shape. A text cell (64 hex characters in a `CHAR` column, or bytes
written into a text column) means the table is not this V2 table; decoding names
it as a stored fault instead of encoding around it, because such data is fixed by
migrating it (`UNHEX` after verifying `SHA2(path,256)`), not by `.encode()` in
the reader. A row that contradicts its own path, hash, revision or column shape
is a server-side fault: it stays fail-closed and answers `503 ACL_UNAVAILABLE`,
never `400 INVALID_ACL_REQUEST`, which consumers read as "the permission service
is unavailable". The natural key needs InnoDB `DYNAMIC` (or `COMPRESSED`) row
format: the primary key is ~1612 bytes, so a `COMPACT` table rejects this DDL
outright instead of truncating an index column.

**Directory identity is the canonical path.** A directory deleted and recreated at
the same path keeps the rules stored for that path: V2 stores no directory birth,
object ID or `lifecycle_ref`, and deleting a directory does not delete its rules.
This is the accepted behaviour for the current version, not an unimplemented
lifecycle binding; a deletion that must revoke access is an explicit rule change.

The internal writer uses the natural row key
`(repo_id,path_hash,subject_type,provider,namespace,external_id)`.
`expected=None` creates; otherwise it compares the current revision. A fresh UUID
`revision` is the retry key: the same row and revision replay successfully;
conflicting content or a stale expected revision fails. Deletes require the
existing revision. Each writer first acquires the library transfer fence
`cfv2:t:` + the first 56 hex characters of SHA256(`seafile_schema:repo_id`),
then locks native `Branch(master)` **before** the ACL row. Native synchronous
copy/move acquires both library fences in repository-ID order and holds them
through publication. Both scopes must have no ACL rows and be non-virtual;
SQL/lock failure or any protected scope denies transfer. The dedicated native
connection releases advisory locks explicitly before returning to the pool. Native final commit takes the same Branch lock before consulting Hub.
All writers must use this protocol; direct SQL bypasses its concurrency guarantee.
Permission decisions may remain valid until their bounded cache expiry.

Authenticated native repo owner/administrator GET:
`api/v2.1/cloudfile/authorization/v1/directory-rules/?repo_id=...&path=...`.
A full system administrator with native `can_manage_library` may also manage
ACL rules, without acquiring file bytes. No global `IsAdminUser` requirement
blocks a delegated repository administrator. Ordinary r/rw file editors are
**not** repo administrators and cannot delegate ACL rules merely because they
can edit files. Etech business login and management scopes stay in Etech.

POST/PUT/DELETE accept a strict rule record:
`repo_id,path,subject_type,namespace,external_id,permission,inherit,share_mode,expected,revision`.
Provider comes only from trusted `CF_ACL_PROVIDER`; a caller cannot override it.
The only configurable directory permissions are **r/rw/invisible**, never
`none`. `revision` uses the existing branch-serialized ACLStore CAS.

Public ACL POST/PUT/DELETE have no separate publication or
`v2_acl_enabled` feature gate: CloudFile V2's directory ACL is built in.
Each write still requires current native repository administrator authority,
valid `r/rw/invisible` input, revision CAS and authoritative SQL; failures
deny or reject the write. Native C/Go checks are likewise built in and
must be deployed from matching source pins, with current subject, final-byte
and Etech Publisher readback acceptance before promoting a shared instance.
Do not treat a Hub-only code update as a safe deployment.

## Content API

Under `api/v2.1/cloudfile/authorization/v1/`:

- `effective-permission/?repo_id=...&path=...&kind=dir|file`
- `shared-directories/` — current subject's eligible existing roots only.
- `directory-entries/?repo_id=...&path=...&offset=0&limit=50` — at most 100 native
  candidates per page, filtered by the same authority. An empty page may have a
  next offset when candidates were hidden. `root_path` is the navigation boundary.
  Optional `with_tags=true` adds current CE repo tags and legacy free tags
  (display-only and marked `read_only=true`; never a new write source) to
  the visible files and directories only, via per-page indexed reads, plus
  `tags_status`. `FAILED` sets item `tags` to null; it never means "no tags" and
  never fails the listing. Tags are not an authorization input.

All require a native session/token, use its username, reject subject overrides,
and return `Cache-Control: no-store`. These are content checks, not management
checks. Effective-permission also requires native C `check_permission_by_path`
for the authenticated username and exact path. Its result can only narrow the
current V2 scope decision: a library `r` with a child `rw` remains writable at
that child, while root/sibling `r` responses have `write=false`.
**Exception, and only there:** when the decision comes from a share root
(`from_rule` and `qualified_root` outside the library root), an absent native
grant (`None`/`none`) does not deny; the share root itself is the authorisation,
because a directory share exists for accounts with no library membership. An
explicit native `invisible`, and every non-share path, still fail closed. No readable
content permission returns HTTP 403; unavailable or invalid native policy
returns HTTP 503. A management role never supplies content `rw`.
Native file `check-access` also uses this authority for repositories with path policy,
so directory-only access does not fail a preliminary whole-library permission
check. Repo API tokens cannot impersonate current users on repositories with path policy.
Whether a repo is protected is answered from the same library rule snapshot
(a virtual repo also checks its origin; an over-budget library is protected).

### Native write entries consume the same share root

The exception above is not only a Hub-side shape. Native upload links, mkdir,
rename, move, delete and seafdav all gate on C's
`seafile_check_permission_by_path`, whose native library answer for a
non-member is "none". C therefore asks this same authority, once, at the exact
path, when -- and only when -- the library gate denied (an RPC *failure* is
propagated, never retried as a share question). The answer is `r`/`rw` for that
path; the library root and every unshared path stay denied, `admin` is never
producible, and the Go/C final publication checks are unchanged.

`/cloudfile/acl/check/` carries the level in `permissions`, aligned with
`checks`, because a second `action=write` probe would double the round trip on
every share-root write. A caller that ignores the field, or an older Hub that
does not send it, keeps the *deny* reading: not "assume rw". The seam is
registered only where the current V2 extension schema exists and an internal Hub channel
is configured; elsewhere a stock CE denial is byte-identical to before.

### Paged CE directory listing

`GET api/v2.1/repos/<repo_id>/dir/?p=...&start=0&limit=200[&if_dir_id=<dir object id>]`
restores the v0.9 page protocol consumed by EAP items-page. It is selected only
by an explicit `start` or `limit`; requests without them keep the CE14 response.

- One native window (`list_dir_by_dir_id`, CE order: directories first, then
  case-insensitive name), `limit` 1–500, default 200. The parent and every child
  are decided by the same Authority as `directory-entries`; CE
  `check_folder_permission` is not used, so a directory-only grant can page its
  folder. Hidden children are omitted with all their metadata.
- `dirent_list` items carry `type`, `id`, `name`, `mtime`, `permission`
  (`r`/`rw`, effective), `parent_dir`, and `size` for files. Modifier, lock,
  starred and thumbnail fields of the unpaged CE response are not included.
  `with_display_metadata=true` adds `tags` and `tag_status` directly to each
  authorized `dirent_list` item; no separate `tag_batch` is returned. Tags retain
  native source, binding ID, name, color and read-only fields. `OK`/[] means no
  tags; `FAILED`/null means unavailable and does not block listing. The same
  bounded batched SQL reader is reused; there are no per-entry HTTP/RPC checks.
  Consumers reuse `user_perm` and each item's `permission` for this content
  read rather than preflight library/directory permission requests; local
  business admission and separate library-management authorization still apply.
- `dir_id` is the listed directory object. `next_start` counts native entries,
  never visible ones: a window whose children are all hidden returns an empty
  `dirent_list` with `has_more=true`. `has_more`/`scan_exhausted` come from the
  native scan, `user_perm` is the effective permission on the folder, and
  `acl_enforced=true` is set only on this fully authorized path.
- `if_dir_id` different from the current object, or a change during the read,
  returns 409 (restart paging). ACL, identity or native failure returns 503 and
  never an unfiltered or truncated page; recursive, ancestor, type and thumbnail
  variants return 400.
- End of scan: version ≥ 1 libraries reject an invalid dirent id when loading a
  directory object, so one extra probed entry is exact. Version 0 libraries
  read the whole set of valid native objects and slice that stable sequence,
  since native listing may skip invalid v0 dirents inside a window. In this
  legacy fallback `start`/`scanned_count` refer to valid native objects
  (not invalid storage slots); it is safe but does not provide the v1+
  per-page performance guarantee.

### P0-C validation (not a deployment sign-off)

The standard Seahub CI collects `tests/` only. The PR workflow now invokes
`cloudfile_ext/v2/tests/test_directory_page.py` and `test_acl_runtime.py`
explicitly in its separately named P0-C step. Synthetic 50/500/5000-entry
test data checks that the Python endpoint requests only one bounded native
window per page, not real disk/network latency.

For actual Dev measurements from a machine that can reach EAP, run the
read-only `scripts/verify_v2_directory_p0c.py` with `--mode eap`, an
EAP admin-api base URL, and `CLOUDFILE_P0C_EAP_BEARER` or
`CLOUDFILE_P0C_COOKIE` supplied via the local environment. Use
`--case '50=/existing/50-entry-dir'` (repeat for known 500/5000-item
directories), `--limit 50` for the tree, and `--limit 200` for the
list. Use `--mode hub` and `CLOUDFILE_P0C_HUB_TOKEN` to verify
`acl_enforced` on the raw Hub response. The probe never logs token,
repo ID, directory path or item names; it makes GET requests only.
It checks page cursor monotonicity and effective permissions, but cannot
certify that hidden data is absent without a known denied-user fixture.
A Dev measurement is still required before claiming EAP UI performance
parity with v0.9.

### Search authorization

`api/v2.1/cloudfile/search/` uses the same Authority as browsing; the
Meilisearch index is never an authorization source.

- The search root must be readable; a directory-only grant may search inside
  its shared root. Libraries with rules are searchable (no 503 on rule-covered
  roots) and hits under rule subtrees are decided, not discarded.
- Candidates are narrowed by a filter built from this principal's rule paths
  in the library snapshot and Authority decisions (`search/acl_filter.py`),
  using only the indexed `path` and `dirs` fields; nothing is re-indexed and
  rule changes apply on the next request. The filter may over-include (a
  non-inherited grant's region, or a hidden rule directory's own document) but
  never excludes a readable object; this is verified against Authority on
  randomized rule trees. Over 256 rule paths, a 32 KiB filter, or an
  over-budget library fall back to per-hit decisions only.
- Every returned hit is decided again by Authority and must still exist with
  its kind **before current CE tags are queried**; denied, missing or wrong-kind
  candidates never enter a tag SQL batch. Cursors bind the library head,
  native grant, status, freshly verified principal and rule rows. Before a
  response is delivered the current user/UID/groups are checked again: a
  snapshot change invalidates the prepared page (503), a lost root grant or
  inactive account returns 403. Tags are display data, not grants.
- **Dev deployment gate:** check the actual Meilisearch `cloudfile_files`
  index settings for filterable `repo_id`, `path`, `dirs` and searchable
  `name`, `tags`. The current search worker writes `dirs` as exact ancestor
  paths, whereas `search/documents.py` also defines a different schema using
  `ancestor_paths`: these fields are not interchangeable. Never assume the
  live index supports filtering merely because one of these is present in
  source code. Do not auto-alter index settings or start an index rebuild.
  A separate local Meilisearch 1.31 fixture accepted the emitted predicates
  and the real `ExistingMeiliIndex.page()` requests. That does **not** replace
  a read-only check or user-scoped search on the existing Dev index.

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

The built-in Etech provider defaults to `etech`. `CF_ACL_PROVIDER` and the server-configured dotted callable
`CF_ACL_SUBJECT_ENSURE(uid, username)` are the subject integration seam. The latter
must call the existing Memberships TTL projector successfully; failure raises.
Only then does Hub read `cf_sso_group_map JOIN GroupUser`. Missing adapter means
503, never stale-group fallback. This package does not claim package A is wired.

### Shared native batch for directory listing

The internal `/cloudfile/acl/check/` accepts the optional exact boolean `"partial": true` **only** for trusted internal JWT calls. Normal calls remain atomic: one denied path denies the entire request. In partial mode, `permissions` has one aligned item per authenticated input path (`"r"`, `"rw"`, or `null` for an inaccessible child), with the same Authority for every item. The C native directory listing uses bounded batches (up to 512 per call), drops null entries and preserves CE listing order. Invalid policy, identity, schema or a failed Hub request never exposes an unfiltered listing. This avoids one HTTP/Redis round trip per directory child while preventing an ACL on an unrelated sibling from hiding the rest of the library.

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

Both native C and Go enforce CloudFile V2 directory ACL unconditionally.
There is no `v2_acl_enabled` setting; neither service may bypass protected
library checks due to missing configuration.

The first supported seam is current-path read/Range and fresh byte uploads /
overwrites, with actual final-diff checks under Branch CAS. C trusted post/put
file calls carry the actor explicitly. Unscoped commits never infer it from commit
metadata. Object-only tickets, native sync and public links on repositories with path policy
remain closed. Native copy/move is closed **throughout ACL mode** until both
source and destination can be proven transactionally; checking an initially
unprotected source is insufficient. Other structural operations on protected
repos remain closed until lifecycle/source/destination checks are implemented.
CF-EDIT remains an independent constraint and provides no ACL grants.

The integrator must verify current subject adapter, native management
credentials, exposed read/write route coverage, lifecycle behavior, and actual
C/Go final-commit enforcement before deploying matching Hub/Server pins.
There is no separate runtime publication switch. This minimal seam is not
full ACL release certification; internal test adapters are not production
authentication.

## Cache Deployment

ACL rules use bounded per-library snapshots in Seahub's configured shared
Django cache, normally Redis. When the default Django cache is per-process
`LocMemCache` (or `DummyCache`), ACL cross-request cache TTL is forced to zero
so another worker cannot retain a stale grant after a local invalidation.
Per-request authority reuse remains enabled. Use a shared cache in production.

With Redis, use `noeviction` or a `volatile-*` policy for the dedicated/shared
cache instance: generation keys do not have TTL, while snapshots do. Avoid
`allkeys-*` policies that may evict generation keys and temporarily expose an
older cache namespace. Failed invalidation or direct SQL rule edits remain
bounded by the configured TTL (default 180 seconds). Do not promise instantaneous
revocation under cache failures. Cache misses read authoritative SQL; SQL errors
never grant access. Tags bypass shared cache entirely and read only authorized
page/search references.

## Built-In Etech Subject Wiring

The default `CF_ACL_SUBJECT_ENSURE` is
`cloudfile_ext.v2.etech_directory.ensure_subject`. It uses the existing EAP
`/eap/cloudDrive/directory/users/{uid}/context` and `/groups?view=entities`
contracts, a short-lived `directory.read` machine JWT, a dedicated autocommit
SQL connection and native shared Redis. No client-supplied member list is trusted.
Only the current UID's native GroupUser rows are refreshed after the existing
bounded TTL; Directory or Redis failure never renews readiness. Entity lookups
create/reuse flat CE Groups keyed by exact type/namespace/external ID, never name.

While the readiness marker is valid, `ensure_subject` returns from a read-only
check (pooled Redis plus the request's Django connection: exact Profile UID
binding and an exact-name active native account) without opening the dedicated connection
or taking the subject lock. A missing, foreign or expired marker, a changed
binding, an inactive account or any check error takes the locked path, which
behaves as before. Readiness lifetime and revocation timing are unchanged.

Staff identity resolution pre-creates a native CE User/Profile only after a fresh
active Directory UID proof. New Etech users require the trusted Directory account
(`employee_no`, currently Etech `account_`) and use `account@auth.local`. Numeric
and named accounts, including `admin`, are ordinary non-staff users. New native
names follow Seafile RPC lowercase normalization; UIDs remain byte-exact; `cfadmin`,
missing/invalid accounts and native name collisions reject creation. Existing
UID owners retain their exact historical native names, independent of contact
email. It creates no OAuth subject; first OAuth/OIDC login
reuses that UID's native account. Existing UID collation aliases and inactive
accounts reject. Local CE users without a Profile UID use a disjoint native
principal and do not inherit external group claims.

Connection settings: `CF_DIRECTORY_URL` is the existing Directory base URL;
`CF_DIRECTORY_KEY_ID` and `CF_DIRECTORY_SECRET` match EAP's scoped service key.
Optional issuer/audience defaults match EAP (`cloudfile-sso` / `eap-directory`).
`CF_DIRECTORY_GROUP_OWNER` is an existing active native service administrator
that owns newly created flat Groups. Redis comes from native `CACHES.default`
LOCATION. These are connection/identity inputs, not feature switches.


OIDC-only login provisioning uses `cloudfile_ext.v2.jit.SQLJITProvisioner` after
ID Token verification and exact signed/UserInfo `userId` agreement, with fresh
active Directory proof. It uses only native User/Profile/SocialAuthUser facts;
no legacy job, audit, outbox or extension schema is required. Staff preparation
never invokes this login adapter. OAuth-only callbacks retain existing-UID
reuse; a second provider adds its own subject binding to the same UID owner.
A native RPC success followed by SQL failure can leave a precreated/unbound
account, as with staff preparation; no password or session is issued on failure.


## 四表运行路由边界（2026-10-21）

默认根路由不再挂载历史 Resource/Intent/SchemaRunner 控制面。原生库/文件读取保留；`/api/v2.1/cloudfile/authorization/v1/` 是当前唯一授权路由前缀，`extensions/authorization/v1/` 的只读别名也已删除。旧目录管理员、独立 ACL/share 持久层、PolicyHost/PolicyCore、资源委托/epoch 票据和其专用部署模块退役。库列表与 Smart Link 只调用现有 `Authority.effective()`；目录 ACL 页面使用现行 DirectoryRules 的行 revision/CAS 协议和 user/org/role 类型。普通浏览器下载、上传与退出继续使用 CE；V2 Agent2、原生 OAuth 与 `/oidc/` 保持现有接线。

`test_root_routes.py` 验证真实根路由解析及旧路由缺席；既有 ACL HTTP、有效权限、原生 Cookie 和 Checkout 用例验证授权及回执。历史源码只用于追溯，不能据其存在恢复额外表或旧运行入口。
