class RepoTag {
  constructor(object) {
    this.id = object.repo_tag_id;
    this.fileCount = object.files_count || 0;
    this.name = object.tag_name;
    this.color = object.tag_color;
    // CloudFile P2-07: the repo-tags list returns is_system for admin-created
    // system tags (CF_ENABLE_TAGS); the used-tag bar shows a lock for them.
    this.isSystem = !!object.is_system;
  }
}

export default RepoTag;
