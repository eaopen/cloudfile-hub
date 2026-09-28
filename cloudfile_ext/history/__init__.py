# -*- coding: utf-8 -*-
"""Pure path-scope helpers for the file/folder history review module (P2-10).

This package registers nothing at runtime; it exists so the folder-history
scope semantics can be unit-tested without Django or a live seaf-server.
"""

from cloudfile_ext.history.scope import touches_folder_paths  # noqa: F401
