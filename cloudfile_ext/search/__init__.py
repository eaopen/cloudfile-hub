# -*- coding: utf-8 -*-
"""Meilisearch indexing and combined property/tag/content retrieval.
Phase P2 -- not implemented yet.

Gated by CF_ENABLE_MEILISEARCH. Indexing runs out of cf-worker rather than in
the request path; this module registers the indexer that worker drives.
"""


def register(registry):
    from cloudfile_ext.features import is_enabled

    if not is_enabled("CF_ENABLE_MEILISEARCH"):
        return
