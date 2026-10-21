"""Compatibility import for the V2 trusted-UID adapter; no separate authority."""
from cloudfile_ext.v2.oauth_identity import (
    UIDBindingError, bind_existing_uid, choose_uid_owner, trusted_uid_mapping)
