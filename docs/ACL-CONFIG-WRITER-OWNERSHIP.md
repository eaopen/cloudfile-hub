# CloudFile ACL configuration modes — Hub #57

**Product decision (2026-10-24):** CloudFile supports both modes with a single
execution layer. **B is the default product approach**; **A is an optional
external-configuration synchronization enhancement**. Each installation and
library selects the approach that fits its operations. This document describes
deployment conventions, not another authorization data model.

## B — default CloudFile management

CloudFile CE owner/admin management is the normal entry point for configuring
native library grants and `cf_dir_acl` directory rules (read/write/invisible,
inheritance, shared roots). Standalone CE/CloudFile must not require an external
business system to set permissions. Reuse CE native grant and existing Hub
management APIs. The full consistent B management UI/API remains an incremental
feature under #57 and needs actual acceptance; **default product positioning
does not assert that every UI operation has already shipped**.

## A — optional external synchronization

When an existing business application has authoritative permission settings,
it may keep its expected configuration and publish it through trusted
`authorization/v1/library-acl-batch` (GET/preview/PUT). The
`ACLStore.replace_owned` implementation takes a complete provider snapshot,
fingerprint/CAS and the declared `managed` natural-key operation scope. It
changes only declared keys; other keys/providers remain untouched. enterprise Directory may
select A for its business-owned libraries. A never replaces CloudFile's ACL
executor or makes external systems mandatory for standalone deployments.

The executable `test_acl_publisher_scope_mock.py` covers intended-key scope,
out-of-scope desired rejection, stale CAS, idempotent replay and simulated
transaction rollback. It does not constitute real MariaDB or end-to-end
publishing acceptance.

## Known management limitation — accepted

When A and B are both authorized to edit the **same** natural key, a
request-declared `managed` key list and a valid CAS do **not** establish
permanent writer ownership. They constrain individual operations and detect
stale snapshots, but do not prevent alternating writes by two administrators.

**Adopt an operational convention rather than implementing an additional
ownership table or enforcement framework now.** This risk is tracked as
a known deployment/management issue, not a blocker for the B default UX.

1. Designate **one normal configuration owner per library**: B on ordinary
   CloudFile installations, or A where a business system synchronizes it.
   A/B may coexist in **different** libraries of the same instance.
2. When a library must have A and B managing different rules, agree explicitly
   on **non-overlapping natural keys** and operators; never schedule both to
   publish the same key concurrently. This is a human/process convention and
   is **not technically enforced**.
3. When changing a library's primary mode, pause the previous writer, inspect
   the current CE library grants and `cf_dir_acl` snapshot, check expected
   versus applied permissions, transfer operational responsibility, then
   resume the new writer.
4. Retain existing native CE owner/admin checks, CAS, bounded snapshots, API
   error and rollback behavior. Do not call them cross-writer isolation.
5. If operational evidence later shows recurring overwrites, unsafe
   multi-team concurrency or material permission incidents, open a focused
   bug/feature and consider the smallest server-side mitigation then.

No second ACL truth, managed-library concept, task queue or distributed
ownership service.

## Next work and acceptance

Proceed with a minimal B management API/UI in small PRs. Keep CE native
library authorization, shared directory roots and User/Org/Role effective
permission semantics consistent with the [#56 contract](./ACL-EFFECTIVE-CONTRACT.md).
A is an optional publication path into the **same** `cf_dir_acl` rows.

Tests should cover B standalone without enterprise Provider, ordinary `rw`
versus owner/admin permissions, optional A publishing with version conflicts,
different libraries using A/B, manual handover, 403/409/503 behavior and
the eventual Hub + Server read/write/Commit checks. Mixed writers to the
same key are a documented operational risk, not a promised enforced block.

**This PR only tests existing A publisher behavior and documents the choice;
it does not change or release either configuration mode.**
