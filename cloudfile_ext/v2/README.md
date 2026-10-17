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

The built-in Etech Directory adapter now connects staff UID pre-creation,
exact organization/role Group mapping and current-user Memberships TTL refresh.
It uses CE User/Profile/Group/GroupUser and the existing group map; no additional
identity tables or feature switches are introduced. See
[ACL_CONTRACT.md](ACL_CONTRACT.md#built-in-etech-subject-wiring) for the existing
EAP contracts and required connection inputs. A first OAuth/OIDC login reuses a
pre-created UID account without inventing an OAuth sub.

Isolated SQL/Redis, HTTP contract and native C/Go tests do not certify a real
Etech DEV installation, its machine credentials, SSO provider or UI workflows.
