"""A CE FileUUIDMap locator uses the same V2 decision as ordinary browsing."""


def scoped_directory_address(request, repo_id, path, kind='dir'):
    from cloudfile_ext.v2.acl_runtime import Authority
    decision = Authority(request.user.username).effective(repo_id, path, kind)
    if not decision.can_read:
        raise PermissionError('Content access denied')
    return dict(root_path=decision.qualified_root, initial_path=path,
                permission=decision.permission)
