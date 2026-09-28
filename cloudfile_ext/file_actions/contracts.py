# -*- coding: utf-8 -*-
"""Versioned, framework-free vocabulary for CloudFile file actions.

This is the narrow contract for all CloudFile clients and downstream
integrations.  An integration may contribute deployment-specific context or
policy inputs, but it must ask the same CloudFile action service to authorize
and execute an action.  Keeping identifiers and mutability here prevents the
Hub UI, a local Agent and an integration from inventing subtly different meanings for
"open", "download" or "edit".
"""

CONTRACT_VERSION = 'cloudfile-file-action/v1'

NATIVE_PREVIEW = 'native-preview'
LOCAL_VIEW = 'local-view'
LOCAL_EDIT = 'local-edit'
CHECKOUT = 'checkout'

FILE_ACTIONS = frozenset((
    NATIVE_PREVIEW,
    LOCAL_VIEW,
    LOCAL_EDIT,
    CHECKOUT,
))

READ_ACTIONS = frozenset((
    NATIVE_PREVIEW,
    LOCAL_VIEW,
))

WRITE_ACTIONS = frozenset((
    LOCAL_EDIT,
    CHECKOUT,
))


def is_known_action(action_id):
    """Return whether *action_id* belongs to the published action vocabulary."""
    return action_id in FILE_ACTIONS


def writes_content(action_id):
    """Return whether an action needs a write permission and server-side fence."""
    if not is_known_action(action_id):
        raise ValueError('Unknown CloudFile file action: %s' % action_id)
    return action_id in WRITE_ACTIONS
