# CloudFile v0.2 Seahub 扩展边界

本仓库以 Seahub 14.0.8 为基础，只承载 CloudFile 通用能力；etech 等项目代码不得直接进入本仓库。

## 固定入口

- `GET /api/v2.1/cloudfile/capabilities/`：公开、只读的运行时能力清单，仅允许输出 `enabled`、`version`、`provider`。
- `/api/v2.1/cloudfile/extensions/<name>/`：部署方扩展的固定命名空间，避免覆盖 Seahub 原有路由。

部署方通过 Seahub 配置注册扩展：

```python
EXTRA_INSTALLED_APPS = ["cloudfile_extensions", "etech_cloudfile"]
CLOUDFILE_EXTENSION_URLCONFS = {
    "etech": "etech_cloudfile.urls",
}
CLOUDFILE_CAPABILITIES = {
    "directory.acl": {"enabled": True, "version": "1"},
}
SITE_ROOT_URLCONF = "cloudfile_extensions.root_urls"
```

能力名称采用小写命名，如 `auth.oidc`、`search.fulltext`、`directory.acl`、`audit.log`、`tag.extended`、`file.lock`。能力端点不得输出密钥、内部地址或项目数据。

CloudFile 不修改桌面端、移动端及同步协议；项目 UI 与业务逻辑应保留在对应项目仓库，通过此扩展边界接入。
