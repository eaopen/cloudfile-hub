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

## 文件动作、锁与本地 Agent

| 方法 | 路径 | 认证 | 说明 |
|---|---|---|---|
| GET | `/api/v2.1/cloudfile/repos/{repo_id}/file-actions/` | 用户 | 根据真实路径权限、扩展名和锁 provider 返回可用动作 |
| POST | `/api/v2.1/cloudfile/repos/{repo_id}/local-sessions/` | 用户 | 创建 `local-view` 或 `local-edit` 一次性 ticket |
| POST | `/api/v2.1/cloudfile/agent-sessions/claim/` | 一次性 ticket | 原子领取 ticket，返回短时文件 capability |
| PATCH | `/api/v2.1/cloudfile/agent-sessions/{session_id}/heartbeat/` | Bearer capability | 续租当前 generation 的本地编辑会话 |
| PUT | `/api/v2.1/cloudfile/agent-sessions/{session_id}/content/` | Bearer capability | `multipart/form-data` 的 `file` 字段回写新版本 |
| POST/DELETE | `/api/v2.1/cloudfile/repos/{repo_id}/checkout/` | 用户 | 创建/释放手工或第三方签出租约；释放必须带 generation |
| GET/PUT/PATCH/DELETE | `/api/v2.1/cloudfile/repos/{repo_id}/file-lock/` | 用户 | 查询、获取、续租、释放文件锁 |
| POST | `/api/v2.1/admin/cloudfile/repos/{repo_id}/file-lock/force-release/` | 管理员 | 按管理员已查看的 generation 强制释放 |

读取动作由 `CF_ENABLE_FILE_PREVIEW`/`CF_ENABLE_LOCAL_APP` 控制；写动作还受 `CF_ENABLE_CHECKOUT`/`CF_ENABLE_FILE_LOCK`、编辑权限和 server 锁 provider 控制。Agent claim/content/heartbeat 不接受普通登录凭据，只接受一次性 ticket 或单会话 capability。

已知限制：会话创建响应当前未返回前端下载函数需要的 `session.file.name`，所以 `.cloudfile` 浏览器下载流程仍为部分完成。

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
