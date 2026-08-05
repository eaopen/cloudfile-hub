# -*- coding: utf-8 -*-
"""Pure file-action policy.

The policy is intentionally independent of Django and Seafile.  That makes
the important safety rule executable in the light-weight test gate: no action
that can write a file is advertised until a server-side lock provider says it
is ready.  A Hub-only "checkout" record would not stop sync, WebDAV or an API
client from overwriting the file, so it is not treated as a lock.
"""

import os


NATIVE_PREVIEW = 'native-preview'
LOCAL_VIEW = 'local-view'
LOCAL_EDIT = 'local-edit'
CHECKOUT = 'checkout'

WRITE_ACTIONS = frozenset((LOCAL_EDIT, CHECKOUT))


def extension(path):
    """Return a lower-case extension without a dot, or an empty string."""
    return os.path.splitext(path or '')[1].lower().lstrip('.')


def _action(action_id, label, description, available=True, reason=''):
    return {
        'id': action_id,
        'label': label,
        'description': description,
        'available': bool(available),
        'reason': reason,
        'writes': action_id in WRITE_ACTIONS,
    }


def actions_for(path, features, preview_extensions, lock_provider_ready=False,
                can_edit=True):
    """Return every applicable action, including safely disabled choices.

    Disabled actions are intentional.  They tell a person *why* an expected
    workflow is unavailable, while the API never exposes a write-capable URL
    until all prerequisites have been met.
    """
    ext = extension(path)
    preview_extensions = frozenset(preview_extensions)
    result = []

    if features.get('CF_ENABLE_FILE_PREVIEW') and ext in preview_extensions:
        result.append(_action(
            NATIVE_PREVIEW, 'Preview in CloudFile',
            'Open the native Seafile preview with the current permission.',
        ))

    if features.get('CF_ENABLE_LOCAL_APP'):
        result.append(_action(
            LOCAL_VIEW, 'Open with local software',
            'Download one short-lived session file for CloudFile Local and the selected professional application.',
        ))
        result.append(_action(
            LOCAL_EDIT, 'Edit with local software',
            'Start a fenced one-file session for CloudFile Local and the selected professional application.',
            available=lock_provider_ready,
            reason='' if lock_provider_ready else 'file_lock_provider_required',
        ))

    if features.get('CF_ENABLE_CHECKOUT'):
        result.append(_action(
            CHECKOUT, 'Check out for editing',
            'Create a server-enforced lease for manual or third-party editing.',
            available=lock_provider_ready,
            reason='' if lock_provider_ready else 'file_lock_provider_required',
        ))

    if not can_edit:
        for action in result:
            if action['writes']:
                action['available'] = False
                action['reason'] = 'edit_permission_required'
    return result
