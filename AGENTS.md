# Repository Guidelines

## Scope and Instruction Hierarchy

- `Scope`: this file applies to the entire repository.
- `Local guides`: `frontend/AGENTS.md` and `seahub/AGENTS.md` take precedence
  for changes in their directories.
- `Change scope`: modify the smallest relevant component; do not reformat
  unrelated files.
- `Purpose`: use this guide for shared expectations and the local guides for
  technology-specific rules.

## Project Layout

- `seahub/`: Django backend; read its local guide before changing backend code.
- `frontend/`: React frontend; read its local guide before changing UI code.
- `tests/`: cross-application Python test support and test scripts.
- `thirdpart/`: shared or vendored Django applications.
- `media/`: static assets, editor resources, and translation files.
- `sql/`: database-dialect-specific SQL.

## Build, Test, and Development Commands

- `pip install -r dev-requirements.txt`: install Python development dependencies.
- `python manage.py runserver`: start the Django server after configuring a
  local Seafile deployment.
- `make dist`: compile locale and static output.
- `frontend/AGENTS.md`: find React commands and prerequisites.
- `seahub/AGENTS.md`: find Django checks and test-environment requirements.

## Commits and Pull Requests

- `Commit subject`: use a concise imperative summary, commonly with `feat:`,
  `fix:`, or `refactor:`; include an issue or PR number when available.
- `Commit scope`: keep each commit focused on one change.
- `Pull request`: describe the user-visible effect, tests run, and linked issue.
- `UI changes`: include screenshots or recordings.
- `Operational changes`: call out migration, configuration, and translation
  updates explicitly.

## Configuration and Security

- `Secrets`: never commit credentials, tokens, or local service paths.
- `Configuration`: use deployment configuration and environment variables for
  sensitive values.
- `Generated files`: review generated static output before committing it.

## CloudFile dev branch: V2.0 only (2026-10-16)

- `dev` is the active **fresh CE14-based CloudFile V2.0** development line. The former v0.9 `dev` source was preserved at `archive/v0.9-dev-20261016` and is no longer an active feature-development baseline. `dev2-clean` remains the explicit source of the V2 promotion.
- Work **only on explicitly approved MVP tasks and directly blocking, minimal correctness/build/test fixes**. Discoveries, performance ideas, extra compatibility, optional API features, additional tables, refactors or improvements **must be recorded for separate user confirmation, not implemented opportunistically**. Existing roadmaps are not development authorization.
- Native Seafile CE14 data and APIs are primary. Exactly three V2 core extension tables have been approved: `cf_library_storage`, `cf_dir_acl`, and `cf_sso_group_map`. No other custom table is pre-approved. Never restore v0.9's 001–042 extension migrations, managed-library guard, independent directory-share/admin tables, legacy task/outbox or old synchronous sharing ledger merely to satisfy an old caller.
- Preserve the source SHA pins in Docker `build/v2/source-set.json`, and keep tests honest: isolated schema/identity and native C/Go byte tests do **not** certify full Seahub Web, OIDC/SSO, scoped ACL final-commit checks, or external application integration.
- The Git branch promotion changes **no databases, file objects, existing containers, registry tags, or deployed hosts**. A new DEV deployment must use a separate backed-up data/config environment and explicit operational validation; do not reuse or overwrite existing v0.9 production volumes by inference.

## CloudFile V2: built-in features are on by default (2026-10-17)

- CloudFile and native Seafile features that are shipped and supported MUST be usable by default. Do not add feature flags, ENABLE booleans, or provider selectors for built-in capabilities. Check the existing implementation and dependencies before proposing a new setting.
- Detect availability from installed schema, actual native support, and required external connections. Missing optional services degrade only their dependent feature, never native file operations. Never treat a failed dependency check as permission to bypass ACL or Checkout Guard.
- Checkout is installed on fresh V2; an existing installation with a verified `cf_edit_guard` must enforce it on **all** native write paths. An existing installation without Guard keeps ordinary optimistic editing; adding Guard requires a controlled migration/restart, not a flag. Never allow an ENABLE=false override of an installed guard.
- `cf_dir_acl` is always enforced when rules exist; use CE native authorization when they do not. Tag uses native CE behavior. Meilisearch enhances search only if a valid external endpoint is configured, and may be unavailable without harming file services.
- Preserve necessary connection/secrets, storage location overrides, security policy, and measured performance tunables (for example cache TTL). Prefer safe defaults, service/schema detection, and internal runtime capability values over exposed configuration.
- Avoid changes to unrelated upstream Seafile feature flags, protocol exposure, and production data migration. Do not create new persistent state, daemon, API, or compatibility layer simply to manage flags. Document removals and test fresh V2, reused CE14 with/without Guard, failure-closed Guard/ACL behavior, and optional-service outages.
- This rule does not authorize roadmap expansions; only implement already approved scope and directly relevant cleanup, with honest validation status.
