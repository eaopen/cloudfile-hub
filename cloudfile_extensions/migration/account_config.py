"""Linux-only immutable CLI credentials, without persistent plaintext copies.

This supplies input, not authorization or a sync launcher. The caller must hold
the actual workspace/attempt guards for the daemon lifetime and independently
check current native identity, library write qualification and effect intent.
"""
from contextlib import contextmanager
from dataclasses import dataclass, field
import fcntl
import os

from ..common.errors import ContractError
from .native_account import NativeImportAccount, read_import_account


@dataclass(frozen=True)
class ImportAccountConfig:
    account: NativeImportAccount = field(repr=False)
    descriptor: int = field(repr=False)

    @property
    def cli_path(self):
        # seaf-cli calls ConfigParser.read repeatedly. Each open gets a new file
        # position, but always the same inherited, sealed snapshot, not the
        # original deployment path. Docker/Linux is intentional, no disk fallback.
        return "/proc/self/fd/" + str(self.descriptor)

    @property
    def pass_fds(self):
        return (self.descriptor,)


@contextmanager
def import_account_config(path):
    """Yield private validated account + immutable input for CLI ``-C``.

    Use ``close_fds=True, pass_fds=config.pass_fds`` for the direct CLI child,
    never place the token in argv/env/logs. Keep this scope through command
    execution. No actual subprocess is created here; a command exit alone is
    not proof of sync completion. The snapshot is intentionally independent of
    later deployment-file replacement; rotation affects the next scope only.
    """
    descriptor = None
    try:
        try:
            if not hasattr(os, "memfd_create") or not os.path.isdir("/proc/self/fd"):
                raise ValueError()
            account = read_import_account(path)
            # The native CLI uses ConfigParser's default interpolation, whereas
            # our deployment reader deliberately disables interpolation. Escape
            # literal percent signs so native usernames retain their exact value.
            user = account.native_username.replace("%", "%%")
            raw = ("[account]\nserver=" + account.server + "\nuser=" + user +
                "\ntoken=" + account.token + "\n").encode("utf-8")
            if len(raw) > 16384:
                raise ValueError()
            descriptor = os.memfd_create("cloudfile-import-account",
                os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            os.fchmod(descriptor, 0o600)
            offset = 0
            while offset < len(raw):
                written = os.write(descriptor, raw[offset:])
                if written <= 0:
                    raise ValueError()
                offset += written
            os.lseek(descriptor, 0, os.SEEK_SET)
            seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
            fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, seals)
            if fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) & seals != seals:
                raise ValueError()
        except Exception:
            # Fail closed on unavailable kernel support, malformed input or I/O;
            # never fall back to an unsealed file or reveal configuration values.
            raise ContractError("IMPORT_ACCOUNT_UNAVAILABLE", "Immutable native import account is unavailable", 503) from None
        yield ImportAccountConfig(account, descriptor)
    finally:
        if descriptor is not None:
            os.close(descriptor)
