# -*- coding: utf-8 -*-
"""Replaces IsProVersion on the two search entry points upstream gates.

Every other search-adjacent endpoint (ItemsSearch, SearchFile, WikiSearch...)
already decides for itself whether to answer, by checking HAS_FILE_SEARCH /
HAS_FILE_SEASEARCH internally. Search and PublishedRepoSearchView are the only
two that additionally require is_pro_version() -- see docs/search.md section 2
for how that was confirmed by grepping every IsProVersion use on the search
path. This permission asks the same "is search available" question those
other endpoints already ask, so a CE deployment with CF_ENABLE_SEARCH on
behaves exactly as Pro would with search configured, and one with it off
still 404s exactly as native CE does.
"""

from rest_framework.permissions import BasePermission


class IsSearchAvailable(BasePermission):

    def has_permission(self, request, *args, **kwargs):
        from seahub.utils import HAS_FILE_SEARCH, HAS_FILE_SEASEARCH
        return HAS_FILE_SEARCH or HAS_FILE_SEASEARCH
