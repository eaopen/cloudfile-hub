# CloudFile V2 effective ACL contract — Hub #56

Status: **executable compatibility baseline, not a new authorization engine**.
See `cloudfile_ext/v2/tests/fixtures/acl_effective_vectors.json` and
`test_acl_effective_vectors.py`.

## Frozen behavior of the current Hub dev implementation

- **Qualification:** CE native library `r/rw` is the usual entry qualification.
  A library with `r` may be **extended to `rw`** by an explicit applicable
  directory rule. This is not the same as **hard read-only repository state**:
  the existing `Authority.effective` repository-status check caps writes to `r`.
  Do not silently change native `r` into a hard ceiling.
- **Rules:** persisted `r`, `rw`, `invisible` only. No stored `none`; it
  denotes no underlying qualification. `inherit=false` applies to the exact
  directory, but cannot bypass an inaccessible ancestor.
- **Within one subject track:** a deeper applicable rule overrides an
  inherited shallower rule. Same-depth Org or Role matches are combined
  conservatively: `invisible` beats positive grants, otherwise `rw > r`.
- **Across subject tracks:** the currently implemented Seafile-Pro-inspired
  order is **User > Org > Role**, independent of path depth. Example:
  a user's `r` on `/A` beats a Role `rw` on `/A/B`. A parent
  `invisible` blocks traversal even if the child has a higher-priority grant.
  This is a deliberate **compatibility baseline**, not a claim that deeper
  path-first precedence has been universally approved. Changing it requires
  a separate Issue #56 decision, migration impact review and matching Server
  native-access tests, not an unnoticed tweak during A/B UI development.
- **Independent shared directory:** without CE library qualification,
  `share_mode=true` with positive `r/rw` creates a navigation root only
  at its specified directory. Neither library root, ancestor nor sibling
  becomes visible. `inherit=false` on the share disallows its descendants
  without another independent share. Deepest applicable explicit share root
  determines the qualified boundary for a path.
- **Subject source:** User UID, Org and Role are derived from verified
  Provider/CE GroupUser; client-supplied claims must never create permissions.
  Unready/disabled principals fail closed. No trust is inferred from `admin`
  account names or Org/Role labels.

## Portable executable vectors

The JSON fixture is a plain input/expected-result format suitable for a
future Server C/Go fixture runner. Fields include `native` (r/rw/null),
`path`, `rules` (type/namespace/external_id/permission/inherit/share_mode),
`hard_readonly`, `groups`, and expected
`permission/qualified_root/from_rule`.

Run targeted Hub test:

```sh
python3 -m unittest cloudfile_ext.v2.tests.test_acl_effective_vectors -v
```

The vectors explicitly cover native qualification, independent share, read
and write overrides, inheritance on/off, User/Org/Role same depth and crossed
depths, same-tier deny/positive merging, inaccessible parents, hard read-only,
principal freshness, publisher A/B-neutral effective decisions and invalid
stored rows. **Passing pure tests is not proof of Server C/Go file read,
download, upload, commit, WebDAV, local editing or Etech runtime permissions.**

## Roadmap to A/B configuration — Hub #57

Keep **one execution layer**. Mode A uses existing
`authorization/v1/library-acl-batch` fingerprint/CAS + explicit natural-key
ownership and CE native library sharing. Mode B uses authorized CE owner/admin
management APIs and the same `cf_dir_acl` Rule rows. The origin of a
configuration must not change its `Authority` decision.

Before enabling both writers, independently test publisher identity, managed
natural-key scope, transfer A↔B, optimistic conflicts (409), authorization
denied (403), internal failure (503), rollback and native API readback.
**A/B write ownership is not established by this read-only test fixture.**
Do not introduce a managed-library table, alternate ACL truth or periodic
reconciliation framework.

## Release gate

The rule matrix must be reviewed with Etech real library/directory samples
and matched by Server native final read/write/commit checks. Do not merge
behavior-changing ACL code merely because the pure contract CI is green.
