# -*- coding: utf-8 -*-
"""Directory-level ACL (v0.8) -- runtime retired, policy module kept.

The v0.8 generation no longer owns any runtime surface: rule storage moved to
``cloudfile_extensions.schema`` (the unified ``cf_dir_acl`` has no ``subject``
column), enforcement moved to the v0.9 scoped core, and the management API
moved to ``cloudfile_extensions.authorization``. Registering the v0.8 readers
here only re-attached a loader that fails closed on every call and denied
plain CE libraries. Nothing is registered any more; ``CF_ENABLE_DIR_ACL`` no
longer has a runtime effect and deployments must serve directory ACL through
the v0.9 authorization routes (``CLOUDFILE_AUTHORIZATION_ENABLED``).

``resolver`` (and its shared case set, ``acl-cases.json``) stays importable
without Django for the cross-language policy tests; the remaining modules are
unregistered legacy code pending deletion.
"""


def register(registry):
    """Retired: the v0.8 ACL runtime must not be re-registered.

    Kept as a no-op so ``apps.py`` and the capability list stay loadable while
    the dead modules are removed incrementally.
    """
    return None
