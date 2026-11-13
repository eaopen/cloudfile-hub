"""Keep native external links closed through the existing restriction setting."""


def require_external_sharing():
    # No ACL scan or protection-state lookup: this is only the existing global restriction.
    from cloudfile_ext.features import is_enabled
    from django.http import Http404
    if is_enabled('CF_ENABLE_SHARE_RESTRICT'):
        raise Http404('External sharing is disabled')
