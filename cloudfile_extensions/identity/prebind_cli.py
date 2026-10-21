"""Local operator prebinding: private fixed configuration and bounded JSONL input."""
import argparse
import json
import os
import stat
import sys
from uuid import uuid4

from ..common.errors import ContractError
from ..common.validation import object_fields
from ..jobs.runtime import connect_database, _unique_object
from .management import IdentityManagement


def load_config(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > 65536):
            raise ValueError("private operator configuration required")
        raw = source.read(65537)
    if len(raw) > 65536:
        raise ValueError("configuration exceeds limit")
    value = json.loads(raw, object_pairs_hook=_unique_object)
    object_fields(value, ("database", "native_schema", "identity_schema", "directory_provider", "actor_user_id", "issuer"))
    object_fields(value["database"], ("CLOUDFILE_DB_HOST", "CLOUDFILE_DB_USER", "CLOUDFILE_DB_NAME"),
                  ("CLOUDFILE_DB_PORT", "CLOUDFILE_DB_PASSWORD"))
    return value


def process(management, issuer, source, emit, *, apply=False):
    failures = 0
    for number in range(1, 10002):
        raw = source.readline(16385)
        if not raw:
            return 1 if failures else 0
        if number > 10000 or len(raw.encode()) > 16384 or not raw.endswith("\n"):
            emit(dict(line=number, status="failed", code="INPUT_LIMIT"))
            return 1
        try:
            row = json.loads(raw, object_pairs_hook=_unique_object)
            object_fields(row, ("userId", "username", "subject", "reason"))
            _, changed = management.prebind(issuer=issuer, subject=row["subject"], user_id=row["userId"],
                username=row["username"], reason=row["reason"], dry_run=not apply)
            emit(dict(line=number, status=("bound" if apply else "would_bind") if changed else "already_bound"))
        except ContractError as error:
            failures += 1
            emit(dict(line=number, status="failed", code=error.code))
            if error.status >= 500:
                return 1
        except (ValueError, TypeError):
            failures += 1
            emit(dict(line=number, status="failed", code="INVALID_REQUEST"))
    return 1


def main(argv=None):
    parser = argparse.ArgumentParser(description="Check or apply existing-account CloudFile identity bindings")
    parser.add_argument("--config", required=True)
    parser.add_argument("--apply", action="store_true")
    arguments = parser.parse_args(argv)
    connection = None
    try:
        config = load_config(arguments.config)
        connection = connect_database(config["database"])
        management = IdentityManagement(connection, native_schema=config["native_schema"],
            identity_schema=config["identity_schema"], directory_provider=config["directory_provider"],
            actor_user_id=config["actor_user_id"], request_id="prebind-" + uuid4().hex)
        return process(management, config["issuer"], sys.stdin,
                       lambda row: print(json.dumps(row), flush=True), apply=arguments.apply)
    except Exception:
        print("CloudFile prebinding failed; check private configuration, schema and authority", file=sys.stderr)
        return 1
    finally:
        if connection is not None:
            connection.close()


if __name__ == "__main__":
    sys.exit(main())
