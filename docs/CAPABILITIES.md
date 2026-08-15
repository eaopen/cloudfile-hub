<!-- generated-by: gsd-doc-writer -->
# Hub 能力矩阵

> 用途：按代码和测试证据标记 Hub/Web/API 的真实能力状态。
> 适用版本：Seafile CE 14.x。
> 状态：已完成（状态快照：`dev`，2026-08-11）。

## 状态口径

| 状态 | 判定 |
|---|---|
| 已完成 | 当前分支已接入运行时，仓内测试通过，且不依赖未实现的 Hub 环节 |
| 验证中 | 实现与单元测试存在，但仍需三仓、真实服务或浏览器端到端验收 |
| 部分完成 | 只有子路径可用，或发现阻断完整流程的仓内缺口 |
| 规划 | 只有开关、占位包或设计注释，没有有效运行时贡献 |
| 暂停 | 已明确停止继续交付；当前代码未发现此类能力 |
| 待确认 | 代码无法证明外部部署、版本或运行结果 |

## 能力总表

| 能力/开关 | 产品定位 | CE 复用 | Hub 新增 | 状态与证据 |
|---|---|---|---|---|
| 扩展框架 | CE 补强 | Seahub AppConfig、URL 与 settings 加载 | Registry、provider、feature 诊断、`cf_worker` | **已完成**；provider/封存测试通过 |
| `CF_ENABLE_SSO` | CE 补强 | OAuth/OIDC、SAML、CAS、LDAP、REMOTE_USER 登录 | 目录 source、组映射、周期/登录后同步、管理 API | **验证中**；26 个目录/对账测试通过，真实 IdP/目录与组写入需集成验收 |
| `CF_ENABLE_DIR_ACL` | Pro 平替 | CE 库/目录权限基线 | 目录规则 API、继承求解、Hub 权限钩子、管理页面 | **验证中**；57 个 ACL 测试通过；不可绕过性依赖 `cloudfile-server` 同语义实现和 `cf_dir_acl` DDL |
| `CF_ENABLE_AUDIT` | Pro 平替 | seafevents `Activity` 事件表 | 管理端只读查询与页面 | **部分完成**；过滤契约测试通过；跨仓 E2E 已查询文件上传、目录创建/重命名事件，其余操作与协议完整性待验证 |
| CE 元数据 / `CF_ENABLE_METADATA` | CE 补强 | `repo_metadata` 前端、API 和 `_is_dir` 记录模型 | 当前 `metadata.register()` 不登记自有行为 | **验证中**；Hub 通路存在，有效运行依赖外部 Metadata Server 与跨仓部署 |
| CE 目录/文件标签 / `CF_ENABLE_TAGS` | CE 补强 | `repo_metadata`、`repo_tags`/`file_tags` 以及目录表格标签编辑 | 与 metadata 共用占位扩展入口，不建立平行标签存储 | **验证中**；文件标签和通用记录链接代码存在，目录绑定、移动跟随与权限尚无本仓 E2E |
| `CF_ENABLE_SEARCH` | Pro 平替 / CE 补强 | SeaSearch/Elasticsearch 查询与 Seahub 结果后处理 | 解开 CloudFile 搜索入口、Meilisearch provider、增量索引 | **验证中**；Meilisearch/过滤测试通过；SeaSearch 与 invisible ACL 组合有已知缺口 |
| `CF_ENABLE_FILE_PREVIEW` | CE 补强 | CE 原生预览 URL 和渲染器 | 权限感知的统一文件动作列表 | **部分完成**；策略测试通过，React 入口缺浏览器自动化测试 |
| `CF_ENABLE_ONLYOFFICE` | CE 复用 | CE 文档配置、编辑器和回调链 | 仓内有回调鉴权/幂等代码 | **部分完成**；`cloudfile_ext.office` 未在 `apps.py` 注册，当前有效行为仍是 CE 原生集成 |
| `CF_ENABLE_FILE_LOCK` | Pro 平替 | Seahub 权限与文件定位 | 锁状态/获取/续租/释放/管理员强制释放 API | **验证中**；Hub 契约测试通过，必须连接 server 侧 `cf_lock_*` RPC 与表 |
| `CF_ENABLE_WATCH` | Pro 平替 | CE `UserMonitoredRepos` 与 monitored-repos API | 直接放开非 Pro gate，并把开关送入页面上下文 | **验证中**；运行时已接线，但没有 CloudFile 专项测试，通知消费链需部署验收 |
| `CF_ENABLE_CONVERT_EXPORT` | 新应用扩展 | CE 下载/导出基础能力 | 未发现注册模块 | **规划** |
| `CF_ENABLE_CHECKOUT` | Pro 平替 | CE 文件权限和版本写入 | `file_actions` 中的带 generation 租约签出/释放 | **验证中**；API 已接线，依赖 server 锁 provider；`checkout/` 包内旧占位说明不是实际入口 |
| `CF_ENABLE_LOCAL_APP` | 新应用扩展 | CE 认证下载与版本写入 | v2 ticket、Agent claim、心跳、带围栏回写 | **验证中**；下载—领取—编辑—写回容器矩阵 14/14 通过（写回已改 `put_file`）；仍缺签名发布包与跨平台升级 |
| `CF_ENABLE_S3_STORAGE` | CE 补强 | CE/S3 存储与 fsck/gc | 本仓仅有离线维护脚本适配，不存在 Hub 注册模块 | **部分完成（Hub 边界）**；部署与存储总状态以 `cloudfile-docker` 为准 |
| `CF_ENABLE_EXTERNAL_SOURCES` | 新应用扩展 | Seahub 列表/文件 API 外形 | local-path provider、授权、只读浏览/下载、overlay、shadow API、Meilisearch 扫描 | **验证中**；72 个相关测试通过，真实 SMB/NFS 挂载、数据库与浏览器流程待验收 |

## 外部依赖边界

| 能力 | 必需外部条件 | 失败策略 |
|---|---|---|
| ACL | `cf_dir_acl` 表和 server/fileserver 强制执行 | Hub 只收紧；缺少底层实现不能视为安全交付 |
| 文件锁/签出/本地编辑 | `cf_lock_*` RPC、`cf_lock_lease`、`cf_edit_session` | provider 不可用时写动作不可用，不退化为 Hub 提示锁 |
| SSO 组织映射 | 选中的 static/external directory、组 owner、`cf_worker` | 未选 source 时不做映射；同步异常记录状态，不阻断登录 |
| 审计 | seafevents 写入 `Activity` | Hub 只读，不制造第二条不完整审计流 |
| 元数据/标签 | Metadata Server、Redis、JWT 与持久化数据库 | 外部服务不可用时显式失败，不影响核心文件读写 |
| Meilisearch | URL、API key、`cf_worker` | provider 配错时显式报错/日志，不静默换后端 |
| 外部源 | 运维挂载、允许根目录、`cf_*` 表 | 越界、穿越、symlink 逃逸均拒绝；仅提供只读内容路径 |

## 不应误读的实现

- `features.py` 中出现开关不代表能力已实现；必须同时看到 `apps.py` 注册、模块贡献和测试。
- 前端 feature gate 只控制展示；所有安全相关接口必须在服务端重复校验。
- `cloudfile_ext/office`、`metadata`、`checkout` 的文件存在不等于它们各自成为有效注册模块；同样，CloudFile `metadata` 扩展是占位不等于 CE 自带的 `repo_metadata` 前端/API 不存在。
- 仓内单元测试通过不证明真实数据库、C/Go 强制层、IdP、Meilisearch、挂载目录或浏览器流程已通过。
