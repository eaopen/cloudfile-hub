# CloudFile V2 clean Hub baseline

This branch starts exactly from upstream haiwen/seahub `15ec1aa7114c013929509e0aad756b5365a29ce6` (2026-10-16). Only the reviewed `cloudfile_ext/v2/` module is added; the old `cloudfile_extensions`, policy job/outbox/session tables, managed-library guard, or 001–042 migration chain **are not imported**.

The isolated module provides an installer/verifier for the approved three tables, native stable-UID/login_name identity binding and single-user CE GroupUser TTL projection with external org/role mapping, plus isolated database tests. These are adapters and testable implementation assets, **not** wired OIDC/Seahub HTTP endpoints or a finished Etech MVP. Authentik/OIDC live authorization, ACL, data-plane writes and final Commit checks remain outstanding.

When integrated later, use real CE session/Native API, fail closed for protected CloudFile resources, and do not let a stale persistent GroupUser bypass TTL. The existing Seafile core must continue working without CloudFile extensions.
