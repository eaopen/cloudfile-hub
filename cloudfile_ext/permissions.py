# -*- coding: utf-8 -*-
"""Single permission-decision facade (permission-tables.md 4.4).

All permission consumers -- web views, REST endpoints, thumbnails, metadata,
search, OnlyOffice, management endpoints -- go through these two entry points.
The decision composes two orthogonal dimensions:

- content: the path-aware native permission (C-side, already narrowed by the
  directory ACL at the seaf-server layer) further narrowed at the Hub;
- manage: library adminship or a covering directory-level admin grant.

This module is a facade, not a re-implementation: the actual decisions live in
cloudfile_ext.acl.service, and check_folder_permission with its 351 call sites
keeps taking exactly the same code path. The facade exists to give the whole
system one named contract -- notably that ``effective_perm`` must always
receive the *path-aware* C result (``seafile_api.check_permission_by_path``),
never the repo-level ``check_permission``, which would drop the C-side
directory-ACL narrowing and could widen access when the Hub and C switches
disagree.
"""

from cloudfile_ext.acl import service


class PermissionService:
    """The one place permission questions get answered."""

    @staticmethod
    def effective_perm(username, repo_id, path, native):
        """Content dimension: narrow a path-aware native by the directory ACL.

        ``native`` must come from ``seafile_api.check_permission_by_path``
        (path-aware, already narrowed at the C layer). Passing a repo-level
        ``check_permission`` result here would silently drop that narrowing.
        """
        return service.apply_dir_acl(username, repo_id, path, native)

    @staticmethod
    def can_manage(username, repo_id, path):
        """Manage dimension: library admin or covering directory admin."""
        return service.can_manage(username, repo_id, path)
