"""Single-file URI transport, never a bearer/file authorization or command.

Only a paired HTTPS origin can be selected by the Agent. URI tickets still need
single-use authoritative session/device proof/current permission consumption.
"""
from dataclasses import dataclass, field
import re
from urllib.parse import parse_qsl, urlencode, urlsplit
from uuid import UUID

from ..common.errors import ContractError
from .device_proof import DeviceChallenge, _decode


@dataclass(frozen=True)
class OpenURI:
    instance: str
    session_id: str
    ticket: str = field(repr=False)


def _validated(value):
    if not isinstance(value, OpenURI) or not isinstance(value.session_id, str) or str(UUID(value.session_id)) != value.session_id:
        raise ValueError()
    # Same deployment origin rules as device proof, no URI-selected endpoint,
    # credentials, path, fragment, redirects or shell options.
    DeviceChallenge(value.instance, value.session_id, value.session_id, "claim",
        "A" * 43, 1, 61, "0" * 64).message()
    if len(value.instance) > 255:
        raise ValueError()
    _decode(value.ticket, 32)
    return value


def make_open_uri(value):
    """Caller must mint/store a real 60-second device-bound session first."""
    _validated(value)
    return "cloudfile-open://v1/open?" + urlencode([
        ("instance", value.instance), ("session", value.session_id), ("ticket", value.ticket)])


def parse_open_uri(raw, *, paired_instances):
    """Strict Agent contract; raw URI must never be logged or persisted.

    The allowlist comes from local confirmed pairing storage, not this URI or
    remote metadata. Unknown origins require explicit pairing, never automatic
    trust/network probing. No application hints or executable arguments accepted.
    """
    try:
        if not isinstance(paired_instances, frozenset) or not paired_instances or len(paired_instances) > 32:
            raise ValueError()
        if (not isinstance(raw, str) or len(raw) > 2048 or not raw.isascii() or
                any(ord(char) < 33 or ord(char) == 127 for char in raw) or
                re.search(r"%(?![0-9A-Fa-f]{2})", raw)):
            raise ValueError()
        parsed = urlsplit(raw)
        if (parsed.scheme != "cloudfile-open" or parsed.netloc != "v1" or parsed.path != "/open"
                or parsed.fragment or parsed.username or parsed.password):
            raise ValueError()
        pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True,
            encoding="utf-8", errors="strict", max_num_fields=3)
        if len(pairs) != 3 or {key for key, _ in pairs} != {"instance", "session", "ticket"}:
            raise ValueError()
        fields = dict(pairs)
        value = _validated(OpenURI(fields["instance"], fields["session"], fields["ticket"]))
        if value.instance not in paired_instances or raw != make_open_uri(value):
            raise ValueError()
        return value
    except (ValueError, TypeError, UnicodeError, AttributeError):
        # Never echo the URI/ticket, even for invalid origin or malformed input.
        raise ContractError("LOCAL_URI_INVALID", "Local open URI is invalid or requires pairing", 400) from None
