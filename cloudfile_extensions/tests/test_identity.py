"""Real JWT cryptography and protocol failures; no live IdP is claimed here."""
import json
import logging
import time
import unittest
from urllib.parse import parse_qs, urlsplit

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.common.http import HttpsJsonClient, read_json_response, trusted_https_url
from cloudfile_extensions.directory.provider import DirectoryProvider
from cloudfile_extensions.identity.oidc import IDTokenValidator, OIDCConfig, OIDCFlow, RestrictedOAuth2Session, SigningKeys
from cloudfile_extensions.identity.service_tokens import ServiceCredential, ServiceTokenVerifier


class ServiceTokenTest(unittest.TestCase):
    def setUp(self):
        self.secret = b"test-only-machine-key-with-at-least-48-test-bytes-length"
        self.credential = ServiceCredential("etech", "https://services.example.com", "cloudfile",
                                            self.secret, frozenset({"authorization.prepare"}))
        self.verifier = ServiceTokenVerifier({"key-1": self.credential}, clock=lambda: 1000)
        self.claims = {"iss": self.credential.issuer, "aud": "cloudfile", "sub": "etech",
                       "iat": 990, "exp": 1100, "jti": "request-1", "scope": "authorization.prepare"}

    def token(self, changes=None, **kwargs):
        return "Bearer " + jwt.encode({**self.claims, **(changes or {})}, self.secret,
                                       algorithm=kwargs.get("algorithm", "HS256"),
                                       headers={"kid": kwargs.get("kid", "key-1")})

    def test_machine_identity_and_scope_are_configured_not_payload_authority(self):
        principal = self.verifier.verify(self.token())
        self.assertEqual(principal.service_id, "etech")
        principal.require("authorization.prepare")
        with self.assertRaises(ContractError) as caught:
            principal.require("directory.admin")
        self.assertEqual(caught.exception.status, 403)

    def test_bad_signature_key_algorithm_scope_time_and_purpose_are_rejected(self):
        bad = [self.token({"aud": "etech"}), self.token({"iss": "wrong"}),
               self.token({"sub": "user-1"}), self.token({"scope": "directory.admin"}),
               self.token({"exp": 1000}), self.token({"exp": 10000}),
               self.token({"iat": "990"}), self.token({"iat": True}),
               self.token({"nbf": 2000}), self.token({"scope": "authorization.prepare authorization.prepare"}),
               self.token(kid="missing"), self.token(algorithm="HS384"),
               self.token().replace("Bearer ", "Token ")]
        for token in bad:
            with self.subTest(token=token[:10]), self.assertRaises(ContractError) as caught:
                self.verifier.verify(token)
            self.assertEqual(caught.exception.status, 401)

    def test_configured_rotation_accepts_only_bounded_registered_keys(self):
        verifier = ServiceTokenVerifier({"key-1": self.credential, "key-2": self.credential}, clock=lambda: 1000)
        self.assertEqual(verifier.verify(self.token(kid="key-2")).service_id, "etech")
        with self.assertRaises(ValueError):
            ServiceCredential("etech", "issuer", "aud", b"weak", frozenset({"read"}))


class OIDCTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def setUp(self):
        self.config = OIDCConfig("https://auth.example.com/application/o/cloudfile/", "cloudfile", "test-only",
                                 "https://files.example.com/oauth/callback/", "https://auth.example.com/authorize/",
                                 "https://auth.example.com/token/", "https://auth.example.com/userinfo/",
                                 "https://auth.example.com/jwks/")
        public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.private.public_key()))
        self.jwks = {"keys": [{**public, "kid": "key-1", "alg": "RS256", "use": "sig"}]}
        self.calls = 0
        class Client:
            def get(inner, url, headers):
                self.calls += 1
                return self.jwks
        self.keys = SigningKeys(self.config.jwks_url, client=Client(), clock=lambda: 10)
        self.validator = IDTokenValidator(self.config, self.keys)
        now = int(time.time())
        self.claims = {"iss": self.config.issuer, "aud": "cloudfile", "sub": "authentik-user-1",
                       "userId": "business-user-1", "nonce": "nonce-1", "iat": now, "exp": now + 300}

    def validate(self, changes=None, **kwargs):
        token = jwt.encode({**self.claims, **(changes or {})}, kwargs.get("private", self.private),
                           algorithm="RS256", headers={"kid": kwargs.get("kid", "key-1")})
        return self.validator.validate(token, nonce=kwargs.get("nonce", "nonce-1"), access_token="access-1",
                                       userinfo=kwargs.get("userinfo", {"sub": "authentik-user-1", "userId": "business-user-1"}))

    def test_verified_business_identity_is_not_email_or_employee_number(self):
        result = self.validate({"email": "employee@example.com", "preferred_username": "E001"})
        self.assertEqual(result["userId"], "business-user-1")
        self.assertEqual(result["sub"], "authentik-user-1")
        self.validate()
        self.assertEqual(self.calls, 1)

    def test_issuer_audience_nonce_signature_userinfo_and_claim_types(self):
        cases = [({"iss": "https://wrong.example.com"}, {}), ({"aud": "wrong"}, {}),
                 ({"exp": self.claims["iat"] - 60}, {}), ({"iat": str(self.claims["iat"])}, {}),
                 ({"userId": 1}, {}), ({"azp": "wrong"}, {}),
                 ({"aud": ["cloudfile", "other"]}, {}), ({"at_hash": "wrong"}, {}),
                 ({}, {"nonce": "wrong"}), ({}, {"private": self.other_private}),
                 ({}, {"userinfo": {"sub": "different"}}),
                 ({}, {"userinfo": {"sub": "authentik-user-1", "userId": "different"}})]
        for changes, kwargs in cases:
            with self.subTest(changes=changes), self.assertRaises(ContractError) as caught:
                self.validate(changes, **kwargs)
            self.assertEqual(caught.exception.status, 401)

    def test_multiaudience_requires_matching_authorized_party(self):
        self.assertEqual(self.validate({"aud": ["cloudfile", "other"], "azp": "cloudfile"})["userId"], "business-user-1")

    def test_jwks_unknown_key_does_not_follow_header_url_and_can_rotate(self):
        self.validate()
        with self.assertRaises(ContractError):
            self.validate(kid="missing")
        self.assertEqual(self.calls, 1)
        self.keys.clock = lambda: 13
        self.jwks["keys"][0]["kid"] = "key-2"
        self.assertEqual(self.validate(kid="key-2")["userId"], "business-user-1")
        self.assertEqual(self.calls, 2)

    def test_authorization_uses_nonce_pkce_and_safe_return_path(self):
        class Transactions:
            def save(inner, state, transaction, binding):
                inner.value = state, transaction, binding
        store = Transactions()
        flow = OIDCFlow(self.config, store, self.validator)
        params = parse_qs(urlsplit(flow.begin("b" * 32, redirect="//evil.example.com")).query)
        self.assertEqual(params["code_challenge_method"], ["S256"])
        self.assertEqual(params["response_type"], ["code"])
        self.assertEqual(store.value[1]["redirect"], "/")
        self.assertEqual(params["nonce"], [store.value[1]["nonce"]])
        self.assertNotIn("client_secret", params)


class HttpBoundaryTest(unittest.TestCase):
    def test_upstream_oauth_diagnostics_cannot_log_tokens_even_at_debug_level(self):
        captured = []
        class Capture(logging.Handler):
            def emit(self, record):
                captured.append(record.getMessage())
        logger = logging.getLogger("requests_oauthlib.oauth2_session")
        handler, prior_level = Capture(), logger.level
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        try:
            session = RestrictedOAuth2Session(client_id="fixture")
            logger.debug("token body: fixture-only-sensitive-text")
            logger.error("request headers: fixture-only-sensitive-text")
            session.close()
            self.assertEqual(captured, [])
        finally:
            logger.removeHandler(handler)
            logger.setLevel(prior_level)

    def test_directory_uses_exact_id_and_never_accepts_invalid_source_as_empty_memberships(self):
        class Client:
            def get(self, url, headers):
                self.url, self.headers = url, headers
                return {"userId": "wrong"}
        client = Client()
        provider = DirectoryProvider("https://directory.example.com/api", authorization=lambda: "Bearer fixture",
                                     attribute_allowlist={"employee_no"}, client=client)
        with self.assertRaises(ContractError) as caught:
            provider.fetch("u/1")
        self.assertEqual(caught.exception.status, 503)
        self.assertEqual(client.url, "https://directory.example.com/api/users/u%2F1/context")
        self.assertEqual(client.headers["Authorization"], "Bearer fixture")

    def test_https_client_disables_redirects_proxies_and_netrc(self):
        class Response:
            status_code = 200
            headers = {"Content-Type": "application/json"}
            def iter_content(self, chunk_size):
                yield b'{"ok":true}'
            def close(self):
                pass
        class Session:
            def get(self, url, **kwargs):
                self.options = kwargs
                return Response()
        session = Session()
        self.assertEqual(HttpsJsonClient(session=session).get("https://directory.example.com/api"), {"ok": True})
        self.assertFalse(session.trust_env)
        self.assertFalse(session.options["allow_redirects"])
        self.assertTrue(session.options["verify"])
        self.assertEqual(session.options["timeout"], (3, 10))

    def test_only_deployment_owned_https_urls_are_accepted(self):
        for url in ("http://directory.example.com", "https://user:pass@example.com", "https://example.com#fragment", "https://example.com?url=other"):
            with self.assertRaises(ValueError):
                trusted_https_url(url)

    def test_oversize_duplicate_fields_and_redirects_are_rejected(self):
        class Response:
            status_code = 200
            headers = {"Content-Type": "application/json"}
            closed = False
            def iter_content(self, chunk_size):
                yield b'{"userId":"u1","userId":"u2"}'
            def close(self):
                self.closed = True
        for size, status in ((1024, 200), (4, 200), (1024, 302)):
            response = Response()
            response.status_code = status
            with self.assertRaises(ContractError):
                read_json_response(response, maximum_bytes=size)
            self.assertTrue(response.closed)
