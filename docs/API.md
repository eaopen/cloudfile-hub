<!-- generated-by: gsd-doc-writer -->
# CloudFile Hub API

> 用途：列出本仓运行时可注册的 CloudFile HTTP 接口及认证/开关边界。
> 适用版本：Seafile CE 14.x。
> 状态：基础接口清单与增补导航。原表来自 2026-08-11；2026-10-13 核对存储 API 并补充设备编辑导航。未逐项复验的旧接口不得视为当前完整 API 清单。

## 约定

- 本页基础接口表中的用户接口沿用 Seahub 的 `TokenAuthentication` 与 `SessionAuthentication`；token 使用 Seahub 原生 `Authorization: Token ...` 形式，浏览器会话使用 CSRF。
- 管理接口使用 `IsAdminUser`；普通用户接口使用 `IsAuthenticated`，并由 `UserRateThrottle` 限流。
- URL 以部署的 Seahub 根地址和 `SITE_ROOT` 为准；本仓不定义生产域名。
- 功能关闭时能力接口返回 404 或根本不注册。前端隐藏入口不是鉴权依据。
- 表中 `{repo_id}` 为 UUID，`{source_id}` 为整数，`{session_id}` 为 UUID。

## 存储类与建库

`CF_ENABLE_S3_STORAGE` 开启时注册；使用 Token/Session 认证、`IsAuthenticated` 与用户限流。

| 方法 | 路径 | 输入/返回与边界 |
| --- | --- | --- |
| GET | `/api/v2.1/cloudfile/storage-classes/` | 返回 `storage_classes` 数组；读取失败为 500 |
| POST | `/api/v2.1/cloudfile/repos/` | `name` 必填，`desc`、`storage_id`、`repo_key` 按配置选用；owner 固定为当前用户。成功 201，返回 `repo_id`，自动分库另返回 `repo_key` 和 `storage_id` |

`repo_key` 只在自动分库模式可用，不与显式 `storage_id` 同传；非法或冲突输入拒绝。接口没有新增用户选择 UI。实现见 [存储视图](../cloudfile_ext/storage/views.py)，配置与迁移见 [存储说明](https://github.com/eaopen/cloudfile-docker/blob/dev/docs/features/storage-backends.md)。

## 设备编辑与新扩展

设备签名与上传使用独立认证流程，不能套用本页基础 Token/Session 约定。入口及恢复语义见 [设备上传契约](https://github.com/eaopen/cloudfile-local-agent/blob/dev/docs/device-upload-contract.md)和[Agent 兼容说明](AGENT-COMPATIBILITY.md)。是否开放由当前版本能力及服务端开关决定。

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

## 文件动作、本地会话与正式库嵌入

2026-10-13 按 `cloudfile_ext/file_actions/__init__.py` 和 `apis.py` 核对：

| 方法 | 路径 | 认证与范围 |
| --- | --- | --- |
| GET | `/api/v2.1/cloudfile/repos/{repo_id}/file-actions/` | 用户认证；按路径权限返回动作，受功能开关限制 |
| GET | `/api/v2.1/cloudfile/integration/v1/resources/resolve/` | 用户认证；`resource_key` 映射到整库根，`view_mode` 只接受 `CFILE_EMBED`；不承诺子目录隔离 |
| POST | `/api/v2.1/cloudfile/repos/{repo_id}/local-sessions/` | `CF_ENABLE_LOCAL_APP`；支持 `local-view` 和需编辑权限的 `local-edit`；`local-edit-exclusive` 返回 503 |
| POST | `/api/v2.1/cloudfile/agent-sessions/claim/` | 一次性 ticket；非法输入 400，过期或不可用 410；不能用普通登录凭据替代 ticket |

旧文档列出的 `agent-sessions/{session_id}/content/`、`heartbeat/`、`repos/{repo_id}/checkout/`、`file-lock/` 与 `force-release/` 不在当前 file_actions 注册表中，不作为接入契约。受控编辑使用独立的 `extensions/local-edit/` 与 `extensions/editing/` 路径，详见 [Agent 兼容](AGENT-COMPATIBILITY.md)。原普通本地会话与设备提交不能互换凭据。

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
