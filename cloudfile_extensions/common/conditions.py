"""Strong HTTP conditions and body revisions serve different error semantics."""

import hmac
import re

from .errors import ContractError, invalid


def require_revision(value):
    if value is None:
        raise ContractError("PRECONDITION_REQUIRED", "A revision is required", 428)
    if not isinstance(value, str) or not value or len(value) > 512:
        raise invalid("Invalid revision")
    return value


def compare_revision(expected, actual):
    expected = require_revision(expected)
    if not isinstance(actual, str) or not hmac.compare_digest(expected.encode(), actual.encode()):
        raise ContractError("RESOURCE_REVISION_CONFLICT", "Resource has changed", 409)


def compare_if_match(header, etag):
    if header is None:
        raise ContractError("PRECONDITION_REQUIRED", "If-Match is required", 428)
    # Wildcards/weak tags cannot protect the version seen by the editing caller.
    if (not isinstance(header, str) or len(header) > 2048 or
            not isinstance(etag, str) or not re.fullmatch(r'"[^"\r\n]+"', etag)):
        raise invalid("Invalid If-Match")
    values = [value.strip() for value in header.split(",")]
    if not values or any(not re.fullmatch(r'"[^"\r\n]+"', value) for value in values):
        raise invalid("A strong If-Match validator is required")
    if not any(hmac.compare_digest(value.encode(), etag.encode()) for value in values):
        raise ContractError("PRECONDITION_FAILED", "Resource has changed", 412)
