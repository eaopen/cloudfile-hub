"""Private deployment seaf-cli account input; not a service/user authorization."""
from configparser import ConfigParser
from dataclasses import dataclass, field
import os
import re
import stat
from urllib.parse import urlsplit

from ..common.errors import ContractError


@dataclass(frozen=True)
class NativeImportAccount:
    server: str = field(repr=False)
    native_username: str = field(repr=False)
    token: str = field(repr=False)
    device: int = field(repr=False)
    inode: int = field(repr=False)
    size: int = field(repr=False)
    modified_ns: int = field(repr=False)
    changed_ns: int = field(repr=False)


def read_import_account(path):
    """Read fixed local account file for trusted import orchestration only.

    No fallback password/login/environment credential is accepted. The launcher
    must use account_config.import_account_config's sealed inherited input, not
    re-open an unchecked path, and independently authorize the current native
    user/library before effects. This reader alone is not launch authority.
    """
    if not isinstance(path, str) or not os.path.isabs(path) or "\0" in path:
        raise ValueError("fixed absolute deployment account file required")
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != os.geteuid() or
                before.st_mode & 0o077 or not 0 < before.st_size <= 16384):
            raise ValueError()
        chunks, size = [], 0
        while chunk := os.read(descriptor, min(4096, 16385 - size)):
            size += len(chunk)
            if size > 16384:
                raise ValueError()
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError()
        config = ConfigParser(interpolation=None, strict=True)
        config.read_string(b"".join(chunks).decode("utf-8"))
        if config.defaults() or config.sections() != ["account"] or set(config["account"]) != {"server", "user", "token"}:
            raise ValueError()
        server, user, token = (config["account"][key] for key in ("server", "user", "token"))
        parsed = urlsplit(server)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or
                parsed.query or parsed.fragment or "%" in server or any(ord(c) < 33 or ord(c) == 127 for c in server) or
                not user or len(user.encode("utf-8")) > 255 or any(ord(c) < 32 or ord(c) == 127 for c in user) or
                not re.fullmatch(r"[A-Za-z0-9._~-]{32,256}", token)):
            raise ValueError()
        # Accessing parsed.port validates malformed ports too.
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError()
        return NativeImportAccount(server.rstrip("/"), user, token, before.st_dev, before.st_ino,
            before.st_size, before.st_mtime_ns, before.st_ctime_ns)
    except Exception:
        raise ContractError("IMPORT_ACCOUNT_UNAVAILABLE", "Private native import account is unavailable", 503) from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
