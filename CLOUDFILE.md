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

当前 migration 建立公共资源、任务及 outbox，并在原 `cf_audit_event` 表上增量扩展；不一次建未来域表。旧审计保留 source/操作人/时间，新增 schema_version=0，不伪造 business userId/event_id/recorded_at。DDL 按实际结构验证和步骤记录恢复；校验和/结构漂移拒绝继续。其余 v0.1 业务表转换、备份恢复演练与启动接入仍须后续验收。

## 身份、上下文与事件内核

`identity/service_tokens.py` 校验已登记的 HS256 机器凭据（kid/issuer/audience/service/scope/短 TTL），支持受控轮换。`identity/oidc.py` 使用已有 requests-oauthlib/PyJWT 完成授权码、PKCE、固定 JWKS/RS256、issuer/audience/azp/nonce/UserInfo sub 和可信 userId 校验；state 在专用 Redis 中一次消费并绑定浏览器。HTTPS JSON 通道限制大小、拒绝重定向和重复 JSON 字段，不读取环境代理/netrc；私有 CA 只能由部署配置可信文件。

这些模块返回已认证事实，不授予库资格；尚未挂到 CE 登录/退出回调、身份预绑定/JIT 和 WebDAV 凭据流程，不能声明完整 auth.oidc。

`directory/provider.py` 按精确 userId 读取固定目录地址。`contexts.py` 只保存 CF 专属 Redis 的最小主体，固定 TTL/向下 jitter、单次源读取、租约和随机 epoch CAS。不要求 etech 新增源版本表；目录必须从主库一致性读取，不使用响应缓存或异步副本；etag 仅表示内容，可选源版本只作诊断。登录、到期或强刷取最新；账号状态/活动屏障优先于缓存 ready。投影与持久协调保护区必须由 CF 原生适配器提供，当前没有生产适配器，不能用空 callback 开放入口。

`jobs/store.py` 持久保存幂等、作用域屏障和 worker 代次；取消/失败不解除屏障，完成必须有可信协调器核对证明。`events/outbox.py` 要求调用方已开启同一 SQL 事务，同时追加审计和 outbox；resource/search 消费者分别领取/确认，不共享 delivered 位。既有自有资源写入可使用真实事件钩子；Server 文件提交/访问来源、消费者领域处理器、审计查询 API 和常驻 worker 接入尚未完成。

CloudFile 不修改桌面端、移动端及同步协议；项目 UI 与业务逻辑应保留在对应项目仓库，通过此扩展边界接入。

待开发的登录方案统一见 `eap-cloudfile/docs/features/identity-directory.md`：持久身份复用 CE 用户/原生 OAuth 绑定，最小属性、组织和角色上下文只缓存 CF 专属 Redis，默认不新增主体快照表。已有账号复用或受控预绑定，新账号经可信目录校验后受控 JIT；有效会话只在上下文缺失/过期时刷新权限，不重复要求 OIDC 登录。此方案尚未在本仓库实现。

## v0.2 显式 OIDC Host

`CLOUDFILE_OIDC_ENABLED=True` 时，app ready 校验 `CLOUDFILE_OIDC_CONFIG`（原始字典或既有 OIDCConfig）、policy config、固定 callback/return URI、数据库 session 与唯一 session middleware。校验通过后接入既有 CloudFile native backend、guarded session middleware 与 late post-fork login resource scope，保留本地恢复认证；不在 app ready 连接 SQL/Redis/IdP，不自动改变 capability。

ROOT_URLCONF 仍由部署设置 `SITE_ROOT_URLCONF='cloudfile_extensions.root_urls'`；显式挂载 `extensions/identity/v1/` 的 begin/callback/pending/logout/idp/return。Gunicorn 使用已有 policy hooks 构造真实 LoginResources；未装 hook 的请求安全拒绝，缺 policy/login runtime 拒绝启动。旧 OAuth 不能并行启用，JIT 默认 false。Docker 变量及示例见 cloudfile-docker/CLOUDFILE.md。

v0.2/v0.3 不交付 Agent；属性标签/搜索/锁/完整审计归 v0.3，本地工作流归 v0.4。版本归属与当前 E2E 缺口见 eap-cloudfile/docs/releases/，旧设计和分项源码保留为 staged。
