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

能力实现注册与配置请求分离。受信应用启动代码可以调用 `registry.register_extension(namespace, name, CapabilityImplementation(...))` 注册自有能力，不得覆盖内建能力或核心路由。未知实现、缺依赖、版本/provider 不匹配时最终 enabled=false。WebDAV 默认关闭声明，只有已启用服务的显式部署标记才允许声明。

## 公共开发基础

`common/` 提供严格 DTO、条件版本和签名分页；`directory/protocol.py` 仅验证目录 DTO，不负责认证。`resources/` 提供不预建文件全集的稀疏属性存储：空读取不建行，首次写通过路径桶锁与完整路径核对防重复，属性和事件同事务，删除重建不能复用旧条件版本。调用方必须提供可信生命周期检查、覆盖 SQL 提交的 Server 写保护区及同事务事件钩子；这些适配未完成前不装载属性 API。

SQL 升级不在正常启动时自动执行。使用 CE 的 mysqlclient 驱动，在 Hub Python 环境设置专用连接 `CLOUDFILE_DB_HOST/PORT/USER/PASSWORD/NAME`；库名指向已确认的 seafile-db，密钥由部署秘密注入。先备份、停写并执行 plan，确认后 apply，启动前 check：

```sh
python -m cloudfile_extensions.schema plan
python -m cloudfile_extensions.schema apply
python -m cloudfile_extensions.schema status
python -m cloudfile_extensions.schema check
```

当前 migration 只建立公共资源表和升级账本，不一次建未来域表。DDL 按实际结构验证和步骤记录恢复；校验和/结构漂移拒绝继续。原 v0.1 业务表数据转换、备份恢复演练、镜像内 CLI 与启动接入仍须后续验收，不能用通用升级测试替代。

CloudFile 不修改桌面端、移动端及同步协议；项目 UI 与业务逻辑应保留在对应项目仓库，通过此扩展边界接入。

待开发的登录方案统一见 `eap-cloudfile/docs/features/identity-directory.md`：持久身份复用 CE 用户/原生 OAuth 绑定，最小属性、组织和角色上下文只缓存 CF 专属 Redis，默认不新增主体快照表。已有账号复用或受控预绑定，新账号经可信目录校验后受控 JIT；有效会话只在上下文缺失/过期时刷新权限，不重复要求 OIDC 登录。此方案尚未在本仓库实现。
