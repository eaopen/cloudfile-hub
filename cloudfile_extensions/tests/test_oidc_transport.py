"""Loopback HTTPS IdP fixture, real OAuth exchange, RSA/JWKS and Redis state.

This tests the protocol adapter, not deployment-specific Authentik/native login.
"""
import base64
from datetime import datetime, timedelta, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import ssl
import tempfile
from threading import Thread
import time
import unittest
from urllib.parse import parse_qs, urlencode, urlsplit
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import jwt
import requests

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.common.http import HttpsJsonClient
from cloudfile_extensions.identity.oidc import IDTokenValidator, OIDCConfig, OIDCFlow, RedisLoginFlows, SigningKeys


@unittest.skipUnless(os.environ.get("CF_TEST_REDIS_PORT"), "requires isolated CloudFile test Redis")
class OIDCTransportTest(unittest.TestCase):
    def setUp(self):
        import redis
        self.redis = redis.Redis(host=os.environ.get("CF_TEST_REDIS_HOST", "127.0.0.1"), port=int(os.environ["CF_TEST_REDIS_PORT"]))
        self.prefix = "cf:oidc:test:" + uuid4().hex + ":"
        self.addCleanup(self.redis.close)
        self.addCleanup(self.cleanup_keys)
        self.directory = tempfile.TemporaryDirectory(prefix="cf-oidc-https-")
        self.addCleanup(self.directory.cleanup)
        self.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public = {**json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.private.public_key())), "kid": "signing-1", "alg": "RS256"}
        now = datetime.now(timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(self.private.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
                .not_valid_after(now + timedelta(hours=1)).add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(self.private, hashes.SHA256()))
        self.ca = Path(self.directory.name) / "ca.pem"
        key_path = Path(self.directory.name) / "key.pem"
        self.ca.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(self.private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        self.codes = {}
        self.token_calls = 0
        self.userinfo_calls = 0
        self.redirect_token = False
        self.bad_nonce = False
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass  # Authorization material must never appear in test logs.

            def json_response(self, value):
                encoded = json.dumps(value).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def do_GET(self):
                parsed = urlsplit(self.path)
                if parsed.path == "/userinfo":
                    owner.userinfo_calls += 1
                if parsed.path == "/authorize":
                    values = parse_qs(parsed.query)
                    if values.get("code_challenge_method") != ["S256"] or values.get("client_id") != ["cloudfile"]:
                        self.send_error(400)
                        return
                    code = uuid4().hex
                    owner.codes[code] = values
                    self.send_response(302)
                    self.send_header("Location", owner.config.redirect_uri + "?" + urlencode({"code": code, "state": values["state"][0]}))
                    self.end_headers()
                elif parsed.path == "/jwks":
                    self.json_response({"keys": [owner.public]})
                elif parsed.path == "/userinfo" and self.headers.get("Authorization") == "Bearer access-1":
                    self.json_response({"sub": "provider-sub-1", "userId": "business-user-1"})
                else:
                    self.send_error(404)

            def do_POST(self):
                if self.path != "/token":
                    self.send_error(404)
                    return
                owner.token_calls += 1
                if owner.redirect_token:
                    self.send_response(302)
                    self.send_header("Location", owner.base + "/userinfo")
                    self.end_headers()
                    return
                values = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
                authorized = owner.codes.pop(values.get("code", [""])[0], None)
                challenge = base64.urlsafe_b64encode(hashlib.sha256(values.get("code_verifier", [""])[0].encode()).digest()).rstrip(b"=").decode()
                expected_basic = "Basic " + base64.b64encode(b"cloudfile:test-secret").decode()
                if (authorized is None or challenge != authorized["code_challenge"][0] or
                        self.headers.get("Authorization") != expected_basic or values.get("grant_type") != ["authorization_code"] or
                        "allow_redirects" in values):
                    self.send_error(400)
                    return
                now = int(time.time())
                claims = {"iss": owner.config.issuer, "aud": "cloudfile", "sub": "provider-sub-1", "userId": "business-user-1",
                          "iat": now, "exp": now + 300, "nonce": "wrong" if owner.bad_nonce else authorized["nonce"][0]}
                token = jwt.encode(claims, owner.private, algorithm="RS256", headers={"kid": "signing-1"})
                self.json_response({"access_token": "access-1", "token_type": "Bearer", "expires_in": 300, "id_token": token})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.addCleanup(self.server.server_close)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(str(self.ca), str(key_path))
        self.server.socket = tls.wrap_socket(self.server.socket, server_side=True)
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)
        self.base = "https://localhost:" + str(self.server.server_port)
        self.config = OIDCConfig(self.base + "/issuer/", "cloudfile", "test-secret", "https://files.example.com/oauth/callback/",
                                 self.base + "/authorize", self.base + "/token", self.base + "/userinfo", self.base + "/jwks", ca_bundle=str(self.ca))
        keys = SigningKeys(self.config.jwks_url, client=HttpsJsonClient(ca_bundle=str(self.ca)))
        self.flow = OIDCFlow(self.config, RedisLoginFlows(self.redis, prefix=self.prefix), IDTokenValidator(self.config, keys))
        self.binding = "browser-binding-" + uuid4().hex

    def stop_server(self):
        self.server.shutdown()
        self.thread.join(timeout=2)

    def cleanup_keys(self):
        keys = list(self.redis.scan_iter(match=self.prefix + "*"))
        if keys:
            self.redis.delete(*keys)

    def authorize(self):
        url = self.flow.begin(self.binding, redirect="/libraries/")
        response = requests.get(url, verify=str(self.ca), timeout=3, allow_redirects=False)
        self.assertEqual(response.status_code, 302)
        return parse_qs(urlsplit(response.headers["Location"]).query)

    def test_real_https_code_pkce_jwks_userinfo_and_single_use_callback(self):
        values = self.authorize()
        identity, redirect = self.flow.complete(state=values["state"][0], code=values["code"][0], binding=self.binding)
        self.assertEqual(identity["userId"], "business-user-1")
        self.assertEqual(redirect, "/libraries/")
        with self.assertRaises(ContractError):
            self.flow.complete(state=values["state"][0], code=values["code"][0], binding=self.binding)
        self.assertEqual(self.token_calls, 1)
        self.assertEqual(self.userinfo_calls, 1)

    def test_token_endpoint_redirect_is_not_followed(self):
        values = self.authorize()
        self.redirect_token = True
        with self.assertRaises(ContractError):
            self.flow.complete(state=values["state"][0], code=values["code"][0], binding=self.binding)
        self.assertEqual(self.userinfo_calls, 0)

    def test_signed_wrong_nonce_is_rejected_after_exchange(self):
        values = self.authorize()
        self.bad_nonce = True
        with self.assertRaises(ContractError) as caught:
            self.flow.complete(state=values["state"][0], code=values["code"][0], binding=self.binding)
        self.assertEqual(caught.exception.status, 401)
