"""External login labels never replace the stable Profile/OIDC binding key."""
import secrets

from ..common.errors import ContractError
from ..common.validation import identifier


def login_name(value):
    identifier(value, maximum=200)
    if value != value.strip() or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("invalid login name")
    return value


def directory_login_name(subject):
    attributes = subject["attributes"]
    name = attributes.get("login_name")
    employee = attributes.get("employee_no")
    if name is not None and employee is not None and name != employee:
        raise ContractError("IDENTITY_CONFLICT", "Directory login labels disagree", 409)
    value = name if name is not None else employee
    if value is None:
        return None
    try:
        return login_name(value)
    except (ValueError, ContractError):
        raise ContractError("IDENTITY_CONFLICT", "Directory login label is invalid", 409) from None


def assert_login_identity(identity, subject):
    """Compare verified claims to one trusted UID snapshot, never to email."""
    if identity["userId"] != subject["userId"]:
        raise ContractError("IDENTITY_CONFLICT", "Directory identity does not match", 409)
    if "login_name" in identity and directory_login_name(subject) != identity["login_name"]:
        raise ContractError("IDENTITY_CONFLICT", "Directory login label does not match", 409)


def new_native_username(subject):
    # Retain the deployed employee account convention only for legacy sources.
    # Generic login names may be emails, Unicode or reused after an employee
    # leaves; an opaque CE name avoids treating those labels as account keys.
    name = directory_login_name(subject)
    if "login_name" not in subject["attributes"] and name is not None:
        if (name.lower() == "cfadmin" or
                not all(c.isascii() and (c.isalnum() or c in "._-") for c in name)):
            raise ContractError("IDENTITY_CONFLICT", "Invalid legacy employee label", 409)
        return name + "@auth.local"
    return secrets.token_hex(16) + "@auth.local"
