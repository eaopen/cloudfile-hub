"""Private operator command: verify one stdin token, revoke its exact jti."""
import argparse
import base64
import json
import os
import stat
import sys

from ..common.validation import object_fields, identifier
from ..jobs.runtime import _unique_object
from .service_tokens import ServiceCredential, ServiceTokenVerifier
from .service_revocations import ServiceRevocations


def load_config(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > 65536):
            raise ValueError("private operator configuration required")
        raw = source.read(65537)
    if len(raw) > 65536:
        raise ValueError("configuration exceeds limit")
    value = json.loads(raw, object_pairs_hook=_unique_object)
    object_fields(value, ("redis", "credentials"), ("prefix",))
    object_fields(value["redis"], ("host", "port", "password"))
    identifier(value["redis"]["host"])
    if type(value["redis"]["port"]) is not int or not 1 <= value["redis"]["port"] <= 65535:
        raise ValueError("invalid redis port")
    if not isinstance(value["redis"]["password"], str) or "\x00" in value["redis"]["password"]:
        raise ValueError("invalid redis password")
    configured = value["credentials"]
    if not isinstance(configured, dict) or not 1 <= len(configured) <= 16:
        raise ValueError("bounded fixed machine credentials required")
    credentials = {}
    for kid, item in configured.items():
        identifier(kid, maximum=64)
        object_fields(item, ("service_id", "issuer", "audience", "secret_base64", "scopes"), ("maximum_ttl",))
        scopes = item["scopes"]
        if (not isinstance(scopes, list) or not 1 <= len(scopes) <= 64
                or any(not isinstance(scope, str) for scope in scopes) or len(set(scopes)) != len(scopes)):
            raise ValueError("invalid machine scopes")
        secret = base64.b64decode(item["secret_base64"], validate=True)
        credentials[kid] = ServiceCredential(item["service_id"], item["issuer"], item["audience"],
            secret, frozenset(scopes), item.get("maximum_ttl", 300))
    return value, credentials


def main(argv=None):
    parser = argparse.ArgumentParser(description="Revoke one verified CloudFile service token")
    parser.add_argument("--config", required=True)
    args = parser.parse_args(argv)
    client = None
    try:
        config, credentials = load_config(args.config)
        # No command-line JWT: shell history/process listings must not expose it.
        raw = sys.stdin.buffer.read(8194)
        if len(raw) > 8193:
            raise ValueError("token exceeds limit")
        token = raw.decode("ascii").removesuffix("\n")
        principal = ServiceTokenVerifier(credentials).verify("Bearer " + token)
        import redis
        settings = config["redis"]
        client = redis.Redis(host=settings["host"], port=settings["port"], db=0,
            password=settings["password"] or None, socket_connect_timeout=1,
            socket_timeout=1, retry_on_timeout=False, decode_responses=False)
        revoked = ServiceRevocations(client, prefix=config.get("prefix", "cf:service-revocations:")).revoke(principal)
        print(json.dumps({"revoked": revoked}))
        return 0
    except Exception:
        print("CloudFile token revocation failed; check private configuration and service state", file=sys.stderr)
        return 1
    finally:
        if client is not None:
            try:
                client.connection_pool.disconnect()
            except Exception:
                pass


if __name__ == "__main__":
    sys.exit(main())
