# -*- coding: utf-8 -*-
"""Named providers: one extension point, several interchangeable backends.

The registry's other hooks are *chains* -- every registered hook runs, and the
question is "does anything want to participate?". A provider answers a
different question: "which single implementation does this job?". Directory
ACL rule sources and the search backend are both that shape. There is exactly
one answer at a time, and an operator picks it by configuration:

    CF_PROVIDER_SEARCH = 'meilisearch'
    CF_PROVIDER_ACL_RULE_SOURCE = 'local-db'

Why this belongs in the baseline while the implementations do not:

    The *seam* -- "search is pluggable", "ACL rules come from somewhere
    pluggable" -- is a property of the framework, and the upstream patch that
    feeds it lives in the baseline too. The implementations (meilisearch,
    seasearch, an external permission service) are capabilities and live on
    capability branches. Adding one is a register_provider() call plus new
    files, never an edit here.

Kind names are free-form strings owned by whoever declares the seam; nothing
in this module knows what capabilities exist. The setting that selects a
provider is derived from the kind, so adding a kind needs no edit here either.
"""

import logging

from django.conf import settings

logger = logging.getLogger(__name__)

#: Selected when the setting is empty. Means "behave like native CE".
NONE = ''


def setting_name(kind):
    """Setting that selects the active provider for `kind`.

    ``'acl_rule_source'`` -> ``'CF_PROVIDER_ACL_RULE_SOURCE'``.
    """
    return 'CF_PROVIDER_%s' % kind.upper().replace('-', '_')


def selected(kind):
    """Name the operator picked for `kind`, or '' when none is configured."""
    return getattr(settings, setting_name(kind), NONE) or NONE


class UnknownProvider(Exception):
    """Configured provider name is not registered.

    Deliberately fatal rather than falling back to the native backend: an
    operator who wrote CF_PROVIDER_SEARCH=meilisearh (typo) asked for
    meilisearch, and silently serving Elasticsearch results instead -- or
    silently serving *no* ACL rules -- is worse than refusing.

    How loud this actually is depends on the caller. Seahub's own search view
    wraps its search_files() call in a bare ``except Exception`` and renders an
    empty result page, so at that entry point this surfaces as "nothing
    matched" plus a log line -- cloudfile_ext.hooks logs it explicitly for
    exactly that reason. Callers inside cloudfile_ext do not swallow it.
    """


class ProviderSet(object):
    """Registered providers, grouped by kind."""

    def __init__(self):
        self._by_kind = {}

    def register(self, kind, name, provider):
        if kind not in self._by_kind:
            self._by_kind[kind] = {}
        if name in self._by_kind[kind]:
            raise ValueError('duplicate %s provider: %s' % (kind, name))
        self._by_kind[kind][name] = provider
        return provider

    def names(self, kind):
        """Registered names for `kind`, sorted. Used by the admin surface."""
        return sorted(self._by_kind.get(kind, {}))

    def active(self, kind):
        """The provider the operator selected, or None when none is.

        Raises UnknownProvider when a name is configured but nothing answers
        to it -- see the exception's docstring for why that is not a warning.
        """
        name = selected(kind)
        if not name:
            return None
        try:
            return self._by_kind[kind][name]
        except KeyError:
            raise UnknownProvider(
                '%s=%r, but the registered %s providers are %r. A capability '
                'that registers it may be switched off.'
                % (setting_name(kind), name, kind, self.names(kind)))

    def describe(self):
        """{kind: {'selected': name, 'available': [...]}} for diagnostics."""
        return {
            kind: {'selected': selected(kind), 'available': self.names(kind)}
            for kind in sorted(self._by_kind)
        }
