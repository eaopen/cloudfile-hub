# CloudFile repository-scoped Checkout (OFF / OPTIONAL)

Decision: 2026-10-25. CloudFile supports exactly two library policies. No REQUIRED mode.

| Library policy | Default | Behavior |
| --- | --- | --- |
| OFF | Yes | Seafile read/write/versioning. No Checkout Guard SQL or native Guard write fence for that repository. |
| OPTIONAL | Explicit Repo UUID allowlist | An authorized user can Checkout a file, Commit repeatedly while retaining Guard, and Checkin to publish and release it. Unchecked-out files remain normally editable. |

**No file-extension-based enablement, mandatory sign-out, extra lock/intent/session
tables, or database-backed per-request library policy checks.**

## Configuration

`CF_ENABLE_CHECKOUT` remains the global capability switch, default `false`.
`CF_CHECKOUT_REPOS` is a comma-separated list of canonical Seafile Repo UUIDs,
default empty. Both must be set to enable a repository. Docker bootstrap writes
the same normalized selection into Hub `CF_CHECKOUT_REPOS` (tuple) and native
`seafile.conf [cloudfile] checkout_repo_ids`, read by both Go and C.
The policy is loaded at startup; change it in a coordinated restart.

No policy fields are added to `cf_library_storage`, which only tracks storage bindings.
No special Etech provider behavior is needed. Etech or other PDM integrations may
opt their chosen libraries into OPTIONAL without modifying normal repositories.

## Runtime boundary

1. On an OFF library, Hub denies exclusive-edit tickets, returns
   `checkout_supported=false` without Guard access, and continues issuing
   authorized `local-view` and `optimistic-edit` tickets.
2. On OFF libraries, C/Go native operations skip Guard SQL and related
   Branch-diff/locking logic entirely. Existing ACL/CAS remain authoritative.
3. On OPTIONAL libraries, the native Guard remains authoritative, including
   ordinary upload and other unscoped write paths. A missing or invalid Guard
   schema fails closed **only for affected libraries**.
4. Agent Rust uses its existing work copy, durable Journal, proof/generation,
   status and explicit Commit/Checkin; it does not implement a parallel policy.
5. Hub PR #50 must query capability only for relevant local actions and allow
   the confirmed owner to resume an existing task. Agent2 #10/#1 require
   real Windows/macOS three-mode end-to-end evidence before release.

## Operations and migration

Never remove a repository from the allowlist, or disable the global capability,
while it holds an active Guard or has unresolved Agent changes. First stop
new Checkouts, resolve Commit/Checkin or Cancel, inspect active lease rows, then
update the deployment config and restart Hub, Go, and C together.

Deployments previously using global Checkout must enumerate still-locked Repo
UUIDs and include them in the new allowlist before rollout. An empty new list
means **all OFF**, not the old global behavior. An invalid UUID list is rejected
at configuration loading. OFF does not implicitly release an old Guard.

## Minimal acceptance

- OFF: view/optimistic edit/normal upload; zero Guard SQL in hot write path.
- OPTIONAL without Guard: ordinary edits and explicit Checkout both available.
- OPTIONAL with active Guard: only owner with proof can Commit/Checkin;
  other writes fail and reads succeed.
- Guard unavailable: OPTIONAL writes fail closed while OFF stays operational.
- Switching OPTIONAL -> OFF requires confirmed lease drain and service restart.
