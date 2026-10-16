# V2 Native Identity Integration

OAuth2 and OIDC use the same native CE account, OAuth binding, Profile, session
and downstream authorization. The stable external UID is mapped to
`Profile.login_id`; email and display name must not be used as identity keys.

## Login Endpoints

- `<SITE_ROOT>oauth/login/`: native OAuth2 code flow using trusted UserInfo.
- `<SITE_ROOT>oidc/login/`: OIDC code flow using the same configured provider and
  native OAuth callback, with a nonce and signed ID Token verification before
  account authentication or session creation.

OIDC uses the existing native `OAUTH_*` client, endpoint, callback and attribute
settings. Configure `OAUTH_OIDC_ISSUER` and `OAUTH_OIDC_JWKS_URI`, include `openid`
in `OAUTH_SCOPE`, and map the trusted stable UID to `login_id` and provider subject
to `uid` in `OAUTH_ATTRIBUTE_MAP`. The issuer and JWKS URI are administrator
configuration. HTTPS is required unless native
`OAUTH_ENABLE_INSECURE_TRANSPORT` is explicitly enabled for the deployment.
No discovery or token-provided key URL is used.

The minimal OIDC adapter supports RS256. It verifies signature, issuer, audience,
expiry, issued-at, nonce, subject, authorized party where applicable, optional
access-token hash, and the UserInfo subject match. JWT validation uses the existing
[PyJWT dependency](https://pyjwt.readthedocs.io/en/2.13.0/api.html).
Missing/mismatched OAuth state or failed OIDC proof is rejected before binding.

`NativeIdentity.bind()` is an internal trusted adapter: callers must validate the
external proof and compare the exact UID against the trusted Directory first.
A second verified binding reuses the native account and its native grants;
case-folded UID aliases and inactive accounts are rejected.

This login integration does not activate directory ACL HTTP services or C/Go file
authorization. Their runtime wiring and real deployment verification are separate
from token/account unit checks.

## Subject TTL Runtime

Work package A connects the reviewed `Memberships` projector to real requests.
`Profile.login_id` stays the single trusted UID anchor; CloudFile adds no second
identity table.

- Both `<SITE_ROOT>oauth/callback/` paths (OAuth2 and OIDC) publish one UID
  subject, fetched now rather than reused from a readiness record, after the
  native login and Profile binding and before the session is returned. A failed
  preparation logs out and refuses the new session.
- Every CloudFile view mounts `permissions.SubjectReady`. Inside the configured
  TTL the published subject is reused; after the TTL the projector re-queries the
  Directory by the current UID and re-projects native `GroupUser`.
- A native account without a `login_id` is `403 CF_SUBJECT_MISSING`; any failed
  or out-of-range refresh is `503 CF_SUBJECT_UNAVAILABLE`. Stale `GroupUser` rows
  and an unproven subject never authorize a CloudFile request.

Configuration is administrator-owned and optional. A deployment that sets no
`CF_DIRECTORY_URL` or machine credentials keeps the native CE login and
authorization path untouched, including CE-only accounts.

| Setting | Meaning | Bound |
| --- | --- | --- |
| `CF_DIRECTORY_URL` | Trusted Directory base URL, exact-UID `GET /users/{uid}/context` | HTTPS origin, no credentials/query/fragment |
| `CF_DIRECTORY_SECRET` | HS256 machine signing key from deployment secrets | at least 32 UTF-8 bytes; never from a request |
| `CF_DIRECTORY_KEY_ID` / `CF_DIRECTORY_ISSUER` / `CF_DIRECTORY_AUDIENCE` / `CF_DIRECTORY_SERVICE_ID` | EAP verifier kid / iss / aud / sub | all required with URL/key |
| `CF_DIRECTORY_PROVIDER` | `cf_sso_group_map.provider` namespace | default `etech` |
| `CF_SUBJECT_TTL` | Published-subject readiness lifetime | default 1800, 30-1800 |
| `CF_DIRECTORY_TIMEOUT` | Per-read network timeout in seconds | default 5, 1-30 |

The Directory client requests `Cache-Control: no-store`, refuses redirects and
oversized or non-JSON bodies, and returns the snapshot unvalidated so
`Memberships.validate_subject` remains the single owner of the subject contract.

One autocommit MySQL connection per worker thread serves the projector and is
revalidated before reuse. Readiness records live in the deployment's Redis
(`CACHES['default']['LOCATION']`); a non-Redis cache denies subjects rather than
falling back to native groups, and no new table is added. B uses `CF_ACL_SUBJECT_ENSURE=cloudfile_ext.v2.runtime.ensure_acl_subject`;
`CF_ACL_PROVIDER` must equal `CF_DIRECTORY_PROVIDER`. Native ACL activation and
public rule publication remain separate deployment/acceptance gates.

Directory requests mint unique 60-second HS256 JWTs with `directory.read` scope.
Static `CF_DIRECTORY_TOKEN` is rejected. Rotate machine credentials in deployment
configuration and restart workers; do not persist issued tokens. The server clock
must be synchronized with EAP. Never reuse browser/admin credentials.

