"""Authorization-code OIDC with fixed issuer, single-use state and PKCE.

OAuth exchanges use requests-oauthlib; cryptographic JWT checks use PyJWT.
This module returns authenticated claims, never grants library membership.
"""

import base64
from dataclasses import dataclass
import hashlib
import hmac
import json
import logging
import os
import secrets
from threading import Lock
import time

import jwt
from requests_oauthlib import OAuth2Session
from redis.exceptions import RedisError

from ..common.errors import ContractError
from ..common.http import HttpsJsonClient, read_json_response, trusted_https_url
from ..common.validation import identifier


def rejected():
    return ContractError("AUTHENTICATION_REQUIRED", "OIDC authentication failed", 401)


class _NoOAuthCredentialLogs(logging.Filter):
    def filter(self, record):
        # Upstream debug diagnostics serialize token bodies and Basic credentials.
        # CloudFile records safe authentication outcomes separately, not those bodies.
        return False


_NO_CREDENTIAL_LOGS = _NoOAuthCredentialLogs()


class RestrictedOAuth2Session(OAuth2Session):
    def __init__(self, *args, **kwargs):
        for name in list(logging.Logger.manager.loggerDict):
            if name == "requests_oauthlib.oauth2_session" or name == "oauthlib" or name.startswith("oauthlib."):
                logging.getLogger(name).addFilter(_NO_CREDENTIAL_LOGS)
        super().__init__(*args, **kwargs)

    def request(self, *args, **kwargs):
        # fetch_token(**kwargs) puts unrecognized arguments into the token BODY;
        # enforce transport options here, not at its public keyword boundary.
        kwargs.update(allow_redirects=False, timeout=(3, 10), stream=True, verify=self.verify)
        response = super().request(*args, **kwargs)
        value = read_json_response(response, maximum_bytes=65536)
        # OAuthlib parses Response.text. Supply only the bounded, duplicate-free
        # JSON already checked above; no unbounded response buffering is needed.
        response._content = json.dumps(value, separators=(",", ":")).encode()
        response._content_consumed = True
        response.encoding = "utf-8"
        return response


@dataclass(frozen=True)
class OIDCConfig:
    issuer: str
    client_id: str
    client_secret: str
    redirect_uri: str
    authorization_url: str
    token_url: str
    userinfo_url: str
    jwks_url: str
    user_id_claim: str = "userId"
    ca_bundle: str = None

    def __post_init__(self):
        for url in (self.issuer, self.redirect_uri, self.authorization_url,
                    self.token_url, self.userinfo_url, self.jwks_url):
            trusted_https_url(url)
        for value in (self.client_id, self.user_id_claim):
            identifier(value)
        if not isinstance(self.client_secret, str) or not self.client_secret:
            raise ValueError("OIDC client secret is required")
        if self.ca_bundle is not None and (not isinstance(self.ca_bundle, str) or not os.path.isfile(self.ca_bundle)):
            raise ValueError("OIDC CA bundle must be a trusted deployment file")


class SigningKeys:
    """Fixed configured JWKS; one bounded refresh on an unknown rotating kid."""
    def __init__(self, url, *, client=None, clock=time.monotonic):
        self.url = trusted_https_url(url)
        self.client = HttpsJsonClient(maximum_bytes=65536) if client is None else client
        self.clock = clock
        self.keys = {}
        self.expires_at = 0
        self.last_refresh = float("-inf")
        self.lock = Lock()

    def get(self, kid):
        identifier(kid, maximum=128)
        with self.lock:
            now = self.clock()
            fresh = now < self.expires_at
            if not fresh or (kid not in self.keys and now - self.last_refresh >= 2):
                self.last_refresh = now
                data = self.client.get(self.url, headers={"Accept": "application/json"})
                raw_keys = data.get("keys")
                if not isinstance(raw_keys, list) or not 1 <= len(raw_keys) <= 16:
                    raise rejected()
                keys = {}
                try:
                    for raw in raw_keys:
                        if not isinstance(raw, dict):
                            raise ValueError()
                        if raw.get("use", "sig") != "sig" or raw.get("kty") != "RSA":
                            continue
                        if raw.get("alg", "RS256") != "RS256":
                            continue
                        key_id = identifier(raw.get("kid"), maximum=128)
                        if key_id in keys or any(name in raw for name in ("d", "p", "q", "dp", "dq", "qi")):
                            raise ValueError()
                        if "key_ops" in raw and raw["key_ops"] != ["verify"]:
                            raise ValueError()
                        key = jwt.PyJWK.from_dict(raw, algorithm="RS256").key
                        if key.key_size < 2048:
                            raise ValueError()
                        keys[key_id] = key
                except (jwt.PyJWTError, ValueError, TypeError, AttributeError, ContractError):
                    raise rejected() from None
                self.keys = keys
                self.expires_at = now + 30
            key = self.keys.get(kid)
            if key is None:
                raise rejected()
            return key


class IDTokenValidator:
    def __init__(self, config, keys):
        self.config = config
        self.keys = keys

    def validate(self, token, *, nonce, access_token, userinfo):
        try:
            if not isinstance(token, str) or len(token) > 32768 or not nonce:
                raise ValueError()
            header = jwt.get_unverified_header(token)
            if header.get("alg") != "RS256" or header.get("crit"):
                raise ValueError()
            key = self.keys.get(header.get("kid"))
            claims = jwt.decode(token, key, algorithms=["RS256"],
                                audience=self.config.client_id, issuer=self.config.issuer,
                                leeway=30, options={"require": ["iss", "sub", "aud", "iat", "exp", "nonce", self.config.user_id_claim]})
            if (type(claims["iat"]) is not int or type(claims["exp"]) is not int or
                    claims["exp"] <= claims["iat"] or
                    ("nbf" in claims and type(claims["nbf"]) is not int) or
                    not isinstance(claims["nonce"], str) or
                    not hmac.compare_digest(claims["nonce"].encode(), nonce.encode())):
                raise ValueError()
            audiences = claims["aud"]
            if isinstance(audiences, list) and len(audiences) > 1 and "azp" not in claims:
                raise ValueError()
            if "azp" in claims and claims["azp"] != self.config.client_id:
                raise ValueError()
            if "sid" in claims:
                identifier(claims["sid"])
            identifier(claims["sub"])
            user_id = identifier(claims[self.config.user_id_claim], maximum=225)
            if not isinstance(userinfo, dict) or userinfo.get("sub") != claims["sub"]:
                raise ValueError()
            if userinfo.get(self.config.user_id_claim, user_id) != user_id:
                raise ValueError()
            if "at_hash" in claims:
                expected = base64.urlsafe_b64encode(hashlib.sha256(access_token.encode()).digest()[:16]).rstrip(b"=").decode()
                if not isinstance(claims["at_hash"], str) or not hmac.compare_digest(expected, claims["at_hash"]):
                    raise ValueError()
            # Only claims verified here can identify the business subject.
            return {"issuer": claims["iss"], "sub": claims["sub"], "userId": user_id,
                    "sid": claims.get("sid"), "expires_at": claims["exp"], "userinfo": userinfo}
        except (jwt.PyJWTError, ValueError, TypeError, AttributeError, ContractError):
            raise rejected() from None


class RedisLoginFlows:
    def __init__(self, redis, *, prefix="cf:oidc:flow:"):
        self.redis = redis
        self.prefix = prefix

    def save(self, state, transaction, binding):
        value = json.dumps({"binding": hashlib.sha256(binding.encode()).hexdigest(), "transaction": transaction}, separators=(",", ":"))
        try:
            if not self.redis.set(self.prefix + hashlib.sha256(state.encode()).hexdigest(), value, ex=300, nx=True):
                raise rejected()
        except RedisError:
            raise ContractError("IDP_STATE_UNAVAILABLE", "Authentication state is unavailable", 503) from None

    def consume(self, state, binding):
        if not isinstance(state, str) or not 32 <= len(state) <= 128 or not isinstance(binding, str) or not binding:
            raise rejected()
        try:
            raw = self.redis.eval('''
            local value = redis.call('GET', KEYS[1])
            if not value then return false end
            local data = cjson.decode(value)
            if data.binding ~= ARGV[1] then return false end
            redis.call('DEL', KEYS[1])
            return value
            ''', 1, self.prefix + hashlib.sha256(state.encode()).hexdigest(), hashlib.sha256(binding.encode()).hexdigest())
        except RedisError:
            raise ContractError("IDP_STATE_UNAVAILABLE", "Authentication state is unavailable", 503) from None
        if not raw:
            raise rejected()
        return json.loads(raw)["transaction"]


class OIDCFlow:
    def __init__(self, config, transactions, validator, *, session_factory=RestrictedOAuth2Session):
        self.config = config
        self.transactions = transactions
        self.validator = validator
        self.session_factory = session_factory

    def begin(self, binding, *, redirect="/"):
        if not isinstance(binding, str) or len(binding) < 32:
            raise rejected()
        # Do not permit the saved return path to become an open redirect.
        if (not isinstance(redirect, str) or not redirect.startswith("/") or
                redirect.startswith("//") or "\\" in redirect or
                any(ord(char) < 32 for char in redirect)):
            redirect = "/"
        state, nonce, verifier = (secrets.token_urlsafe(32) for _ in range(3))
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        session = self.session_factory(client_id=self.config.client_id, scope=["openid", "profile", "email"],
                                       redirect_uri=self.config.redirect_uri)
        try:
            url, actual_state = session.authorization_url(self.config.authorization_url, state=state,
                                                          nonce=nonce, code_challenge=challenge,
                                                          code_challenge_method="S256")
            if actual_state != state:
                raise rejected()
            self.transactions.save(state, {"nonce": nonce, "verifier": verifier, "redirect": redirect}, binding)
            return url
        finally:
            session.close()

    def complete(self, *, state, code, binding):
        transaction = self.transactions.consume(state, binding)
        if not isinstance(code, str) or not code or len(code) > 4096:
            raise rejected()
        session = self.session_factory(client_id=self.config.client_id, scope=["openid", "profile", "email"],
                                       redirect_uri=self.config.redirect_uri, state=state)
        session.trust_env = False
        session.verify = self.config.ca_bundle or True
        try:
            token = session.fetch_token(self.config.token_url, code=code, client_secret=self.config.client_secret,
                                        code_verifier=transaction["verifier"], timeout=(3, 10))
            if not isinstance(token.get("access_token"), str) or token.get("token_type", "").lower() != "bearer":
                raise rejected()
            userinfo = read_json_response(session.get(self.config.userinfo_url, timeout=(3, 10),
                                                      allow_redirects=False, stream=True), maximum_bytes=65536)
            identity = self.validator.validate(token.get("id_token"), nonce=transaction["nonce"],
                                               access_token=token["access_token"], userinfo=userinfo)
            return identity, transaction["redirect"]
        except ContractError:
            raise
        except Exception:
            # Network/library errors must not include tokens or authorization codes.
            raise rejected() from None
        finally:
            session.close()
