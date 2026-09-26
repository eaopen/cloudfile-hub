"""No-session exact-user directory fetch; no BPM/shared Redis fallback."""

from urllib.parse import quote

from ..common.http import HttpsJsonClient, trusted_https_url
from ..common.errors import ContractError, invalid
from ..common.validation import identifier
from .protocol import validate_subject


class DirectoryProvider:
    def __init__(self, base_url, *, authorization, attribute_allowlist, client=None):
        self.base_url = trusted_https_url(base_url).rstrip("/")
        if not callable(authorization):
            raise ValueError("directory machine credential supplier is required")
        self.authorization = authorization
        self.attribute_allowlist = frozenset(attribute_allowlist)
        self.client = HttpsJsonClient() if client is None else client

    def fetch(self, user_id):
        identifier(user_id, maximum=225)
        if user_id in {".", ".."}:
            raise invalid("userId cannot be a path traversal segment")
        url = self.base_url + "/users/" + quote(user_id, safe="") + "/context"
        try:
            value = self.client.get(url, headers={"Authorization": self.authorization(), "Accept": "application/json"})
            return validate_subject(value, requested_user_id=user_id,
                                    attribute_allowlist=self.attribute_allowlist)
        except ContractError as error:
            if error.code == "UPSTREAM_NOT_FOUND":
                raise ContractError("SUBJECT_NOT_FOUND", "Directory subject does not exist", 404) from None
            if error.status == 400:
                raise ContractError("UPSTREAM_UNAVAILABLE", "Directory returned an invalid subject", 503) from None
            raise
