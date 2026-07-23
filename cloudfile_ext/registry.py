# -*- coding: utf-8 -*-
"""CloudFile internal extension registry.

This is deliberately *not* a general plugin platform. It is an in-process
registry that lets each cloudfile_ext submodule declare what it contributes,
so that adding a capability never means editing a central dispatch table (and
never means editing upstream Seahub).

Registration happens during ``CloudFileConfig.ready()``; lookups happen at
request time. Registering after startup is not supported.

Hook points:

``urls``                 extra URL patterns, assembled by cloudfile_ext.urls
``menu``                 navigation/menu entries surfaced to the frontend
``permission_check``     narrow an already-computed permission (never widen)
``file_op``              pre/post hooks around file operations
``search_indexer``       feed documents to an external index
``external_source``      SMB/NFS-style read-only providers
``periodic_task``        recurring work run by the cf_worker process
"""

import logging

logger = logging.getLogger(__name__)

FILE_OP_PHASES = ('pre', 'post')


class Registry(object):

    def __init__(self):
        self.urls = []
        self.menu = []
        self.permission_checks = []
        self.file_op_hooks = {phase: [] for phase in FILE_OP_PHASES}
        self.search_indexers = []
        self.external_sources = {}
        self.periodic_tasks = []
        self._sealed = False

    # -- registration -----------------------------------------------------

    def _check_open(self, what):
        if self._sealed:
            raise RuntimeError(
                'cannot register %s after startup; register it in '
                'CloudFileConfig.ready()' % what)

    def register_urls(self, patterns):
        """Add URL patterns. `patterns` is a list of django.urls entries."""
        self._check_open('urls')
        self.urls.extend(patterns)

    def register_menu(self, entry):
        """Add a menu entry: {'key', 'label', 'url', 'feature'}.

        `feature` names the CF_ENABLE_* switch that gates the entry; it is
        re-checked at render time so toggling a switch does not need a restart
        of the registry itself.
        """
        self._check_open('menu')
        self.menu.append(entry)

    def register_permission_check(self, func):
        """Add a permission narrowing hook.

        Signature: ``func(username, repo_id, path, permission) -> permission``

        Hooks run in registration order, each receiving the previous result.
        A hook must only ever return a permission that is at most as
        privileged as the one it was given -- see docs/acl-semantics.md.
        """
        self._check_open('permission checks')
        self.permission_checks.append(func)
        return func

    def register_file_op_hook(self, phase, func):
        """Add a file operation hook. `phase` is 'pre' or 'post'.

        Signature: ``func(op, username, repo_id, path, **kwargs)``. A 'pre'
        hook may raise to veto the operation; a 'post' hook's exceptions are
        logged and swallowed so that auditing can never break a file write.
        """
        self._check_open('file op hooks')
        if phase not in FILE_OP_PHASES:
            raise ValueError('unknown file op phase: %s' % phase)
        self.file_op_hooks[phase].append(func)
        return func

    def register_search_indexer(self, indexer):
        self._check_open('search indexers')
        self.search_indexers.append(indexer)
        return indexer

    def register_external_source_provider(self, source_type, provider):
        self._check_open('external sources')
        if source_type in self.external_sources:
            raise ValueError('duplicate external source type: %s' % source_type)
        self.external_sources[source_type] = provider
        return provider

    def register_periodic_task(self, name, interval, func):
        """Add recurring work for the cf_worker process to run.

        `interval` is in seconds. Tasks run in one process, one after another,
        so a task that blocks delays the others -- keep them short and let them
        pick up where they left off on the next tick.
        """
        self._check_open('periodic tasks')
        self.periodic_tasks.append({
            'name': name,
            'interval': interval,
            'func': func,
        })
        return func

    def seal(self):
        """Close the registry once app startup has finished."""
        self._sealed = True

    # -- dispatch ---------------------------------------------------------

    def apply_permission_checks(self, username, repo_id, path, permission):
        """Run every permission hook in order, threading the result through."""
        for func in self.permission_checks:
            permission = func(username, repo_id, path, permission)
            if permission is None:
                return None
        return permission

    def run_file_op_hooks(self, phase, op, username, repo_id, path, **kwargs):
        for func in self.file_op_hooks[phase]:
            if phase == 'post':
                # Auditing and indexing must never break the operation they
                # observe -- it has already happened by this point.
                try:
                    func(op, username, repo_id, path, **kwargs)
                except Exception:
                    logger.exception('cloudfile post file-op hook failed: %s', func)
            else:
                func(op, username, repo_id, path, **kwargs)


#: Process-wide registry.
registry = Registry()
