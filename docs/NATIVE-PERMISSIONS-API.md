# CloudFile B mode — native library and directory permissions API

**Development contract for Hub #57; PR is not yet a released API.**
No UI is implemented. B is CloudFile's normal permission management mode;
A remains an optional external batch publisher. Both use Seafile CE native
library shares plus the single `cf_dir_acl` table and Hub/Server authority.

## CE library user/group grants (new)

`/api/v2.1/cloudfile/authorization/v1/library-grants/`

Authenticated via the existing CE token or browser session. Every request
calls `require_repo_manage()`, checking active CE account and actual
repo owner/admin or appropriate library-management staff permission. An
ordinary content `rw` grant is NOT enough to configure anyone's access.
Virtual repos are not managed here; use their CE origin/owner scope.

```http
GET /api/v2.1/cloudfile/authorization/v1/library-grants/?repo_id=00000000-0000-4000-8000-000000000001
```

Response describes **current CE facts**, not an A/B configuration source.
`is_admin` is read from CE's existing elevated-share markers in two bounded
queries rather than per-recipient database queries:

```json
{
  "repo_id": "00000000-0000-4000-8000-000000000001",
  "owner": "owner@auth.local",
  "source": "seafile-ce",
  "grants": [
    {"subject_type":"user","subject":"worker@auth.local","permission":"r","is_admin":false},
    {"subject_type":"group","subject":7,"permission":"rw","is_admin":false}
  ]
}
```

`PUT` creates or changes one direct CE share to a registered active native
account or an existing native group. `permission` is **only `r` or `rw`**,
not `admin`, `invisible`, custom permission or a client-supplied UID:

```json
{
  "repo_id": "00000000-0000-4000-8000-000000000001",
  "subject_type": "user",
  "subject": "worker@auth.local",
  "expected_permission": "r",
  "permission": "rw"
}
```

For a new share use `"expected_permission": null`. For a native group,
`"subject_type":"group"` and `"subject":7` (positive integer).

`DELETE` uses the same payload **without** `permission`; it removes one
share. After native CE RPC, both operations reread the matching CE grant and
return `changed=true/false`. If readback cannot confirm the result, the API
reports an unavailable/unknown operation result rather than inventing success.

`expected_permission` detects stale client state before the RPC (HTTP 409),
but CE's native share update is **not an atomic CAS**. Never claim it prevents
two authorized writers from racing. A/B same-library writer conflicts remain
the accepted operational limitation: use one primary configuration owner per
library; make any A→B handover deliberately after checking the applied rules.

The API deliberately does not change native CE library administrator grants,
which are additionally marked by `ExtraSharePermission` /
`ExtraGroupsSharePermission`. Use the existing CE administrator lifecycle
for those rather than passing a forged `admin` permission.

For a group-owned library (`<group_id>@seafile_group`), the owning group is
group ownership rather than a removable r/rw grant. It is therefore not listed
in `grants` and cannot be changed through this API, matching Seafile's own
share listings; ordinary user/group grants of that library remain manageable.

## Directory ACL (existing, reused)

`/api/v2.1/cloudfile/authorization/v1/directory-rules/`

- `GET ?repo_id=<uuid>&path=/Directory`: list persisted `cf_dir_acl` rules at
  that exact path and CE directory-existence status.
- `POST` / `PUT` / `DELETE`: one rule using the existing complete payload:
  `repo_id, path, subject_type, namespace, external_id, permission, inherit,
  share_mode, expected, revision`. The last two fields are actual rule
  revisions; the client supplies a fresh UUID `revision` for the write.
  `expected=null` creates; existing rule changes require its exact revision.
- `permission` is `r/rw/invisible`; `inherit` and `share_mode` are booleans.
  A share root must be a non-root positive rule, and does not reveal its parent
  or sibling paths.
- A trusted enterprise Directory UID/Org/Role identity and native CE subject
  must be kept separate. No display name, employee number or client-supplied
  group text is authorization evidence.
- Existing `DirectoryRules` is **not** replaced by a second B ACL store.
  For CE-only deployments, default native-directory principal/provider
  consistency must be checked alongside [Hub #61](https://github.com/eaopen/cloudfile-hub/pull/61)
  before claiming the entire user/group directory-ACL experience is released.

### Responses and boundaries

The API uses existing `Cache-Control: no-store` responses. Bad payloads: 400;
non-admin access: 403; stale expected permission/rule revision: 409; unknown
native CE failures: 503. A successful library write is confirmed against
native CE readback; no secondary CloudFile library-grant database is updated.

No bulk mixed CE-library-share + `cf_dir_acl` transaction is promised. A
native CE RPC and a Hub ACL SQL transaction cannot be made atomic without
a substantial new system, which this product does not need. Configure and
verify them as separate steps, with operator-managed recovery on uncertain
results.

## Release checks

- CE-only user/group library grant lifecycle, owner/admin vs ordinary `rw`,
  protected `admin` share, unknown subjects, stale `expected`, readback
  failure and idempotent retry.
- Etech (optional Directory), native CE group sharing and directory ACL
  `r/rw/invisible`, `inherit`, shared root, permission reduction.
- CE read/write, file download and Commit finalization must match Hub #56
  and Server #31; do not rely only on GET response or mock CI.
- A-mode publisher remains available with its own existing fingerprint/CAS;
  never imply its configuration is stored in this B endpoint.
- No UI, no new database tables, no implicit A/B enforcement service.

The lightweight GitHub tests verify the pure native CE RPC adapter with mocks.
Real CE 14 + MariaDB + Etech DEV authorization remains to be verified before
merging/enabling the feature in a release.
