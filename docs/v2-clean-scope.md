# CloudFile Hub V2 当前代码范围

> 2026-10-21：本仓 `dev` 是 Seafile CE14 上的 CloudFile V2 当前开发主线。原始 2026-10-16 clean source 快照仅为历史构建来源说明，不代表当前 `dev` 完全不含旧源码。

真正运行的权限 API 以 `cloudfile_ext/v2/` 和 Seafile/Seahub 当前原生接缝为准。原有 `cloudfile_extensions/` 及旧 `cloudfile_ext/acl/` 的过期模型、SQL、测试不是当前授权事实，必须不得重新注册路由、复制 DDL 或作为上线验证。

当前五张扩展表是 `cf_library_storage`、`cf_dir_acl`、`cf_sso_group_map`、`cf_edit_guard`、`cf_audit_event`。不存在托管库模式；库根资格按 CE，目录及共享根按 V2 Authority，文件实际字节与 Commit 在 Server/Go 终判。参见 `cloudfile_ext/v2/ACL_CONTRACT.md` 及根 `AGENTS.md`。
