# -*- coding: utf-8 -*-
"""Operation log and audit trail. Phase P1 -- not implemented yet.

Gated by CF_ENABLE_AUDIT. When built, this registers a post file-op hook to
record operations and query routes to read them back. Post hooks are
exception-swallowing by design (see registry.run_file_op_hooks) so that
auditing can never break the write it is observing.
"""


def register(registry):
    from cloudfile_ext.features import is_enabled

    if not is_enabled("CF_ENABLE_AUDIT"):
        return
