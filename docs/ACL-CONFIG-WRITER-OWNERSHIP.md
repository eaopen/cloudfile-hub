# CloudFile ACL configuration writers — Hub #57

This note accompanies the **existing** A-mode batch publisher; it does not
activate a new B-mode permission management feature.

## One executable ACL truth

Both external configuration (A) and CloudFile native management (B) must
ultimately write the same CE library grant facts and the same
`cf_dir_acl` rows, which are evaluated by Hub `Authority` and Server final
permission checks. A publisher label is not a user/org/role permission and
must not change any of the [#56 vectors](./ACL-EFFECTIVE-CONTRACT.md).

## What existing A mode already guarantees

`LibraryACLBatch` reads a bounded complete **provider** snapshot and uses
a fingerprint including row revisions. `ACLStore.replace_owned()` locks the
native master branch, checks that fingerprint, then inserts/updates/deletes
only the **natural keys included in the caller's `managed` set**.
An out-of-set desired rule fails before writing. Unlisted keys and rows
belonging to another subject provider remain unchanged. Stale fingerprints
return a conflict rather than silently overwriting updates.

The executable `test_acl_publisher_scope_mock.py` checks declared keys,
out-of-scope desired rules, untouched other-provider rows, CAS conflicts,
idempotent replay and a simulated SQL error rollback. It is a **mocked
transaction**, not real MariaDB validation.

## Important unresolved ownership boundary

A request-supplied `managed` set is an intended *operation scope*, **not
proof of which writer owns a rule**. `require_repo_manage()` verifies the
caller's CE repository administration right, but neither that authorization
nor a CAS fingerprint prevents another authorized writer from naming the same
natural key. Today `DirectoryRules.mutate()` and
`LibraryACLBatch.replace_owned()` both target the same provider namespace
when configured that way.

Therefore **do not enable concurrent A and B writes to the same natural key**
until an explicit ownership rule is enforced. For a small team, prefer one
writer per library during initial rollout, with an operator-reviewed snapshot
and planned handover A↔B. Preserve the existing provider/subject identity
semantics; do not pretend `provider` denotes the publisher. Do not create a
second managed-library table, shadow ACL store or periodic reconciler.

## Next smallest #57 implementation decision

Before enabling a native B management UI/API, review and choose a single
minimal ownership gate (e.g. an explicit library-level configuration owner
with a controlled handover). It must be enforced server-side in both A and B
write routes, not accepted solely from a client claim. Existing deployments
using per-rule endpoints require compatibility checks before changing the
default. Do not claim these mock tests solve A/B ownership.

Subsequent acceptance: owner/admin vs ordinary `rw` user, cross-library
isolation, managed-key scope, 409/403/503 response handling, existing revision
CAS, native CE library sharing, A/B handover and actual Server C/Go final
read/write/commit checks. **No deployment or authorization semantics change
in this test-only PR.**
