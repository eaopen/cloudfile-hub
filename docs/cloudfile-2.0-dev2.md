# CloudFile 2.0 Hub dev2 第一批实现

> 2026-10-16 · 源码开发分支 `dev2`，**不是 2.0 已发行或可替换现有服务的证据**。

本分支保留了 `dev` 已验证的 CE 14.0.8 Web/API、SSO、目录 ACL、真实文件入口和版本功能；不是 7 月 `dev14` 的空白重写。差异通过后续小批清理逐项收敛。应用主登录始终独立，旁路 SSO 失败不可影响 Etech 主业务。

## 本次最小行为改动

- 一份 `cf_dir_acl` 同时表达目录内容权限和 `share_mode`；共享根只能绑定**正向 r/rw** 的非根目录规则，`none/invisible` 不得制造独立共享资格。
- 管理分级权限 `manage_auth` 留在 Etech 业务控制面，不进入 CloudFile 内容授权。
- 与 Server 的终判同步校验非法持久 ACL；文件字节、最终提交仍依赖原有原生执行点，不能因 API 返回成功跳过最终授权。
- 现有 `cf_managed_library` 旧受管库守卫、SchemaRunner 001–042 与当前 API 暂不删除；直接删除可能导致旧入口宽权限回退。仅在 2.0 新装 Schema、切换门禁和数据迁移验收完成之后退场。

## 首版验证边界

本次新增 `CloudFileV2SharingContractTest` 检查授权不放宽不变量；完整 Python/C、真实 MySQL、Etech SSO/ACL/文件上传、跨仓构建与 DEV 部署分别执行，不把静态合同或 CI 合格等同于业务验收。

后续 M1/M2 重点：`login_name + external_user_id` 身份绑定与组 TTL 投影、仅两张核心执行事实的新装 Schema、去掉旧受管/管理授权表的**安全迁移**、EAP 两表发布回执兼容、路径 ACL 在真实文件读写与 Branch 提交终判，以及 Etech 真实用户联验。当前不可标记这些为已完成。
