# CloudFile v0.2 Seahub 扩展边界

本仓库以 Seahub 14.0.8 为基础，只承载 CloudFile 通用能力；项目代码不得直接进入本仓库。产品范围与设计以 `eap-cloudfile` 仓库为准，本文件只说明已实现的扩展装载边界，不表示业务特性已交付。

## 固定入口

- `GET /api/v2.1/cloudfile/capabilities/`：公开、只读的运行时能力清单，仅允许输出 `enabled`、`version`、`provider`。
- `/api/v2.1/cloudfile/extensions/<name>/`：部署方扩展的固定命名空间，避免覆盖 Seahub 原有路由。

部署方通过 Seahub 配置注册扩展：

```python
EXTRA_INSTALLED_APPS = ["cloudfile_extensions", "deployment_adapter"]
CLOUDFILE_EXTENSION_URLCONFS = {
    "adapter": "deployment_adapter.urls",
}
CLOUDFILE_CAPABILITIES = {
    "directory.acl": {"enabled": False, "version": "1"},
}
SITE_ROOT_URLCONF = "cloudfile_extensions.root_urls"
```

示例适配包由部署方提供，不随 CloudFile 发布。能力名称采用小写命名，如 `auth.oidc`、`directory.acl`、`audit.log`、`tag.extended`、`file.lock`；资源检索与文件正文全文检索应分别声明，不能用尚未实现的全文能力代表名称/标签搜索。能力端点不得输出密钥、内部地址或项目数据，业务特性未完成验收时不得仅靠配置声明为可用。

CloudFile 不修改桌面端、移动端及同步协议；项目 UI 与业务逻辑应保留在对应项目仓库，通过此扩展边界接入。

待开发的登录方案统一见 `eap-cloudfile/docs/features/identity-directory.md`：持久身份复用 CE 用户/原生 OAuth 绑定，最小属性、组织和角色上下文只缓存 CF 专属 Redis，默认不新增主体快照表。已有账号复用或受控预绑定，新账号经可信目录校验后受控 JIT；有效会话只在上下文缺失/过期时刷新权限，不重复要求 OIDC 登录。此方案尚未在本仓库实现。
