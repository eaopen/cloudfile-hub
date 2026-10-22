<!-- generated-by: gsd-doc-writer -->
# CloudFile Hub API

> 用途：列出本仓运行时可注册的 CloudFile HTTP 接口及认证/开关边界。
> 适用版本：Seafile CE 14.x。
> 状态：已完成（路由与视图方法已核对，2026-08-11；真实部署联调仍按能力状态执行）。

## 约定

- 用户接口沿用 Seahub 的 `TokenAuthentication` 与 `SessionAuthentication`；token 使用 Seahub 原生 `Authorization: Token ...` 形式，浏览器会话使用 CSRF。
- 管理接口使用 `IsAdminUser`；普通用户接口使用 `IsAuthenticated`，并由 `UserRateThrottle` 限流。
- URL 以部署的 Seahub 根地址和 `SITE_ROOT` 为准；本仓不定义生产域名。
- 功能关闭时能力接口返回 404 或根本不注册。前端隐藏入口不是鉴权依据。
- 表中 `{repo_id}` 为 UUID，`{source_id}` 为整数，`{session_id}` 为 UUID。

## 框架

| 方法 | 路径 | 认证 | 开关 | 说明 |
|---|---|---|---|---|
| GET | `/api/v2.1/cloudfile/features/` | 用户 | 始终注册 | 返回全部开关、provider selected/available 和菜单项 |

## 目录 ACL

| 方法 | 路径 | 认证 | 说明 |
|---|---|---|---|
| GET/POST/DELETE | `/api/v2.1/cloudfile/repos/{repo_id}/dir-acl/` | 用户 | 查询、新增/更新、删除当前用户有权管理的目录规则 |
| GET | `/api/v2.1/cloudfile/repos/{repo_id}/dir-acl/effective/` | 用户 | 解释指定路径/用户的有效权限 |
| GET/POST/DELETE | `/api/v2.1/admin/cloudfile/repos/{repo_id}/dir-acl/` | 管理员 | 管理员绕过规则自身的锁出风险管理 ACL |

全部接口由 `CF_ENABLE_DIR_ACL` 控制。规则主体类型为 `user`、`dept`、`group`；权限为 `rw`、`r`、`none`、`invisible`，路径由服务端规范化。

## SSO 组织映射

| 方法 | 路径 | 认证 | 说明 |
|---|---|---|---|
| GET | `/api/v2.1/admin/cloudfile/sso/sync/` | 管理员 | 查看 source、上次同步状态与映射摘要 |
| POST | `/api/v2.1/admin/cloudfile/sso/sync/` | 管理员 | 触发一次同步 |
| GET/DELETE | `/api/v2.1/admin/cloudfile/sso/group-map/` | 管理员 | 列出映射或解除一个受管组映射 |
| POST | `/api/v2.1/cloudfile/sso/directory-webhook/` | 共享 secret | 接收目录变更通知并触发同步 |

这些接口由 `CF_ENABLE_SSO` 控制。Webhook 不使用 Seahub 用户登录，而是按 `CF_SERVICE_SSO_DIRECTORY_SECRET` 验证；具体 SSO/Authentik 部署说明由跨仓文档维护。

## 审计

| 方法 | 路径 | 认证 | 说明 |
|---|---|---|---|
| GET | `/api/v2.1/cloudfile/audit/` | 管理员 | 分页查询 `Activity` 中的文件/目录事件 |

支持 `repo_id`、`user`、`op_type`、`obj_type`、`page`、`per_page`；`per_page` 最大 200。`op_type` 允许 `create`、`edit`、`delete`、`rename`、`move`、`recover`，由 `CF_ENABLE_AUDIT` 控制。
该接口查询资料库提交差异，不返回预览、读取、下载或分享链接访问事件。

## 搜索

| 方法 | 路径 | 认证 | 说明 |
|---|---|---|---|
| GET | `/api2/search/` | 用户 | 覆盖上游 Pro gate，继续使用上游请求/响应形状 |
| GET | `/api/v2.1/published-repo-search/` | 读者 | 覆盖上游公开库搜索 gate |

由 `CF_ENABLE_SEARCH` 控制。`CF_PROVIDER_SEARCH=''` 保持原生 SeaSearch/Elasticsearch；`meilisearch` 才进入 CloudFile provider。

## 监控（CE 路径复用）

| 方法 | 路径 | 认证 | 说明 |
|---|---|---|---|
| POST | `/api/v2.1/monitored-repos/` | 用户 | 复用 CE endpoint 监控一个有权限访问的库 |
| DELETE | `/api/v2.1/monitored-repos/{repo_id}/` | 用户 | 取消当前用户的库监控 |

`CF_ENABLE_WATCH` 只把上游 `is_pro_version()` gate 扩展为“Pro 或 CloudFile 开关开启”；模型、接口形状和缓存仍由 CE 提供。当前没有 CloudFile 专项测试或通知消费链的本仓验收。

## 文件动作与本地 Agent

| 方法 | 路径 | 认证 | 说明 |
|---|---|---|---|
| GET | `/api/v2.1/cloudfile/repos/{repo_id}/file-actions/` | 用户 | 根据真实路径权限、扩展名和锁 provider 返回可用动作 |
| POST | `/api/v2.1/cloudfile/edit/v1/open/` | 用户 | 按 `{repo_id, path, mode}` 签发 scoped JWT，返回 `cloudfile-open://v2/open?instance=&session=&ticket=` |
| GET | `/api/v2.1/cloudfile/edit/v1/lock-info/` | 用户 | 查当前 Checkout 可见性（`?repo_id=&path=`）；只读，不是发布凭据 |

`mode` 只有三个值，能力由签发方与数据面共同执行：

| mode | 允许的数据面操作 | 前置条件 |
|---|---|---|
| `local-view` | 仅 `read` | 用户对目标路径可读；只读是硬限制，不因账号可写而放宽 |
| `optimistic-edit` | `read` / `status` / `publish`（`X-CF-Action: optimistic`） | 用户可写；不创建 Guard，Checkout 关闭时仍可用 |
| `exclusive-edit` | `checkout` / `renew` / `release` / `publish` | `CF_ENABLE_CHECKOUT` 开启且 `cf_edit_guard` 可用，否则 409 |

票据是 HS256 scoped JWT（`iss=cloudfile-v2-edit`、`aud=cloudfile-edit-agent`、`exp` 上限 **24 小时（86400 秒）**），绑定 `repo_id`/`path`/`file_id`/`mode`。有效期按一个工作日给：Guard 租约只有 10 分钟且靠 `renew` 滚动续期，票据却是硬过期，1 小时会让长编辑在 Guard 仍有效时被 401 打断。Hub 的 `MAX_TICKET_SECONDS` 与 Go fileserver `cfEditClaimsFor` 的 24 小时上限必须同批发布，改一处而漏另一处会让所有票据被服务端拒绝。Agent 只拿到这枚票据，不接收浏览器 cookie、完整 API token 或 Seafile 登录凭据。数据面在 Go fileserver 的 `/seafhttp/cf-edit/v1/*`，每次请求重新判定权限并校验原生 `file_id`；服务端不保存 Session/Intent/Device 表，独占编辑只写 `cf_edit_guard` 单行，未确认任务留在 Agent 本地 Journal。

已退役且不得按旧契约开发：`POST /api/v2.1/cloudfile/repos/{repo_id}/local-sessions/`、`POST /api/v2.1/cloudfile/agent-sessions/claim/`、`PATCH .../agent-sessions/{session_id}/heartbeat/`、`PUT .../agent-sessions/{session_id}/content/`。一次性 ticket 换 capability 的通道已删除，调用不会获得服务。

未启用（2026-10-21 决定：不启用，无实际使用）：`POST/DELETE /api/v2.1/cloudfile/repos/{repo_id}/checkout/`、`GET/PUT/PATCH/DELETE /api/v2.1/cloudfile/repos/{repo_id}/file-lock/`、`POST /api/v2.1/admin/cloudfile/repos/{repo_id}/file-lock/force-release/`。Hub 侧没有注册这三个前缀，`CF_ENABLE_FILE_LOCK` 保持关闭，前端 `seafile-api.js` 的 `lockfile`/`unlockfile` 只在开关打开时才会走到该路径，因此维持现状、不补路由也不改调用点。锁与 Checkout 的执行面在 C/Go 侧，独占编辑请走本文上面的 `exclusive-edit`。

## 外部文件源

| 方法 | 路径 | 认证 | 说明 |
|---|---|---|---|
| GET | `/api/v2.1/cloudfile/external-sources/` | 用户 | 列出当前用户可读的外部源 |
| GET | `/api/v2.1/cloudfile/external-sources/{source_id}/dir/` | 用户 | 浏览目录，查询参数 `p` |
| GET | `/api/v2.1/cloudfile/external-sources/{source_id}/file/` | 用户 | 查看/下载文件，查询参数 `p` |
| GET | `/api/v2.1/cloudfile/external-sources/search/` | 用户 | 搜索已授权外部源 |
| GET/PUT | `/api/v2.1/cloudfile/external-sources/{source_id}/overlay/` | 用户 | 读取/更新路径 metadata/tags overlay |
| GET/POST | `/api/v2.1/admin/cloudfile/external-sources/` | 管理员 | 列出/创建 source |
| PUT/DELETE | `/api/v2.1/admin/cloudfile/external-sources/{source_id}/` | 管理员 | 更新/删除 source |
| GET/POST/DELETE | `/api/v2.1/admin/cloudfile/external-sources/{source_id}/grants/` | 管理员 | 管理 user/group 只读授权 |

由 `CF_ENABLE_EXTERNAL_SOURCES` 控制。内容路径每次访问都重新做允许根目录、路径穿越和 symlink 逃逸校验。

### 原生路径 Shadow

启用外部源时还会在原生路由之前注册下列 shadow：

```text
/api/v2.1/repos/
/api/v2.1/repos/{repo_id}/
/api/v2.1/repos/{repo_id}/dir/
/api/v2.1/repos/{repo_id}/file/
/api2/repos/{repo_id}/file/
/api2/repos/{repo_id}/file/detail/
```

合成 repo ID 由 CloudFile 只读处理；真实 repo ID 委派回上游视图。外部源不进入 repo/commit/block 模型，因此不提供写入、历史、WebDAV、同步或 zip 能力。

## 页面路由

以下为服务端页面入口，不是稳定的外部 REST 契约：

- `/cloudfile/acl/`
- `/cloudfile/audit/`
- `/cloudfile/external-sources/`
- `/cloudfile/file-actions/`

OnlyOffice 的 `onlyoffice/editor-callback/` 保护视图虽然存在于代码中，但当前未由 `CloudFileConfig.ready()` 注册，不能列为有效 CloudFile API。
