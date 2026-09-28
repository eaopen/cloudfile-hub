# -*- coding: utf-8 -*-
"""Favorites (starred items) keyed by object id.

CloudFile changes the native Seafile favorite from ``repo_id + path`` to the
object's unique id (the file obj_id or directory id), so a favorite survives
move and rename. The pure identity rules live in ``identity.py`` and are free
of Django / DB / Seafile imports (see cloudfile-hub/AGENTS.md rule 4); the
Django glue lives in ``seahub.utils.star`` and the ``UserStarredFiles`` manager,
both gated on ``CF_ENABLE_FAVORITES_ID``.
"""
