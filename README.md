# CloudFile Hub

[English](README.md) | [简体中文](README.zh-CN.md)

CloudFile's Web/API layer, maintained as a fork of Seahub against the Seafile CE 14 baseline. It reuses CE Web, API, authentication and preview capabilities, adding enterprise integration and collaboration in `cloudfile_ext/` and `frontend/src/cloudfile/`.

[Product documentation](https://github.com/eaopen/cloudfile/blob/main/docs/en/README.md). Technical references linked here are in Chinese unless indicated otherwise. The original capability snapshot dates to 2026-08-11; use the documentation and checks matching your installed release.

## Scope

| Area | Responsibility |
| --- | --- |
| CE reuse | Authentication, library/directory/file APIs, baseline permissions, native previews and SeaSearch/Elasticsearch paths |
| CloudFile extensions | Extension registration, directory ACLs, organization mapping, auditing, Meilisearch, external sources, file actions and local application sessions |
| External components | Server enforces low-level permissions and locks; Docker handles builds, configuration, database schema and deployment; operators provide search, identity, directory services and mounts |

Hub is part of a multi-repository system:

```text
workspace/
├── cloudfile-server/
├── cloudfile-hub/
└── cloudfile-docker/
```

Deployment and shared contracts are maintained in `cloudfile-docker`. This repository documents the Hub/Web/API implementation.

## Status

- The extension framework and feature flags are implemented. New capabilities default to disabled; selected defaults follow deployment configuration. Disabling all extensions does not remove baseline compatibility patches.
- The historical snapshot recorded `217 passed` for Hub extension tests. This is not a current test run or system acceptance result.
- ACLs, search, external sources, SSO mapping, auditing and file actions have implementations. Check the dated [capability snapshot (Chinese)](docs/CAPABILITIES.md) and the selected release for support and gaps.
- CloudFile's own metadata/tag extension was a placeholder in that snapshot; CE provides metadata and tag APIs/UI. Tag definitions and directory/file binding have separate validation scopes. Conversion and monitoring must not be described as accepted merely because code exists.

## Verification

```bash
.venv/bin/python -m pytest cloudfile_ext/ -q
```

With sibling repositories and dependencies available:

```bash
../cloudfile-docker/tools/run-checks.sh
```

## Documentation

These references are currently in Chinese:

- [Index](docs/README.md) and [architecture](docs/ARCHITECTURE.md)
- [Extension registry](docs/EXTENSIONS.md) and [capability snapshot](docs/CAPABILITIES.md)
- [API](docs/API.md) and [configuration](docs/CONFIGURATION.md)
- [Testing](docs/TESTING.md) and [local professional applications](docs/local-professional-software.md)

Development rules: [AGENTS.md](AGENTS.md). Upstream introduction and licensing: [README.markdown](README.markdown) and [LICENSE.txt](LICENSE.txt).
