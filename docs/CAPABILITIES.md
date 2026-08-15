<!-- generated-by: gsd-doc-writer -->
# Hub 能力矩阵

> 用途：按代码和测试证据标记 Hub/Web/API 的真实能力状态。
> 适用版本：Seafile CE 14.x。
> 状态：已完成（状态快照：`dev`，2026-08-15；状态已与 `cloudfile-docker/docs/feature-matrix.md` 对齐）。

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
| `CF_ENABLE_SSO` | CE 补强 | OAuth/OIDC、SAML、CAS、LDAP、REMOTE_USER 登录 | 目录 source、组映射、周期/登录后同步、管理 API | **已完成**；26 个目录/对账测试通过，static 目录语义跨仓容器 E2E 通过；`external-service` 有代码和单测；LDAP/AD/Authentik 目录源未做专属 provider 验证，只同步已存在用户的组关系 |
| `CF_ENABLE_DIR_ACL` | Pro 平替 | CE 库/目录权限基线 | 目录规则 API、继承求解、Hub 权限钩子、管理页面 | **已完成**；57 个 ACL 测试通过，跨仓容器矩阵 37/37（六入口 + 即时撤权 + 管理员清空） |
| `CF_ENABLE_AUDIT` | Pro 平替 | seafevents `Activity` 事件表 | 管理端只读查询与页面 | **验证中**；过滤契约测试通过，跨仓容器矩阵已覆盖目录创建/重命名、文件上传、移动、删除与恢复查询；不覆盖读取/下载访问日志、合规审计与长期留存 |
| CE 元数据 / `CF_ENABLE_METADATA` | CE 补强 | `repo_metadata` 前端、API 和 `_is_dir` 记录模型 | 当前 `metadata.register()` 不登记自有行为 | **验证中**；Hub 通路存在，依赖外部 Metadata Server；自定义属性列已改为按列名键写入，待复验 |
| CE 目录/文件标签 / `CF_ENABLE_TAGS` | CE 补强 | `repo_metadata`、`repo_tags`/`file_tags` 以及目录表格标签编辑 | 与 metadata 共用占位扩展入口，不建立平行标签存储 | **验证中**；跨仓 E2E 已验证标签创建、绑定、反查、重命名/移动跟随与恢复；自定义属性跟随仍待修复 |
| `CF_ENABLE_SEARCH` | Pro 平替 / CE 补强 | SeaSearch/Elasticsearch 查询与 Seahub 结果后处理 | 解开 CloudFile 搜索入口、Meilisearch provider、增量索引 | **部分完成**；Meilisearch/过滤测试通过；SeaSearch 的 ACL `invisible` 过滤缺口为上游限制（跨用户契约红测，Meilisearch 走同一过滤分支） |
| `CF_ENABLE_FILE_PREVIEW` | CE 补强 | CE 原生预览 URL 和渲染器 | 权限感知的统一文件动作列表 | **验证中**；策略测试通过，React 入口缺浏览器自动化测试；CloudFile 不实现渲染器 |
| `CF_ENABLE_ONLYOFFICE` | CE 复用 | CE 文档配置、编辑器和回调链 | 仓内有回调鉴权/幂等代码 | **部分完成**；`cloudfile_ext.office` 未在 `apps.py` 注册，当前有效行为仍是 CE 原生集成；缺容器级验收 |
| `CF_ENABLE_FILE_LOCK` | Pro 平替 | Seahub 权限与文件定位 | 锁状态/获取/续租/释放/管理员强制释放 API | **部分完成**；Hub 契约测试通过，锁/签入签出/续租/管理员恢复跨协议矩阵 18/21；剩余 WebDAV/REST 拒绝状态码未统一为 423 |
| `CF_ENABLE_WATCH` | Pro 平替 | CE `UserMonitoredRepos` 与 monitored-repos API | 直接放开非 Pro gate（`monitored_repos.py` 上游补丁） | **部分完成**；运行时已接线，没有 CloudFile 专项测试；通知消费链与各格式写回无独立 E2E |
| `CF_ENABLE_CONVERT_EXPORT` | 新应用扩展 | CE 下载/导出与 SeaDoc | 未发现注册模块 | **部分完成（Hub 边界）**；Hub 无自研渲染/转换，跨仓复用 CE/SeaDoc + Compose 配置与前端接线，各格式写回无独立 E2E |
| `CF_ENABLE_CHECKOUT` | Pro 平替 | CE 文件权限和版本写入 | `file_actions` 中的带 generation 租约签出/释放 | **部分完成**；API 已接线，依赖 server 锁 provider；签出/释放跨协议矩阵同文件锁 18/21（`checkout/` 包内旧占位说明不是实际入口） |
| `CF_ENABLE_LOCAL_APP` | 新应用扩展 | CE 认证下载与版本写入 | v2 ticket、Agent claim、心跳、带围栏回写 | **验证中**；下载—领取—编辑—写回容器矩阵 14/14 通过（写回已改 `put_file`）；仍缺签名发布包与跨平台升级 |
| `CF_ENABLE_S3_STORAGE` | CE 补强 | CE/S3 存储与 fsck/gc | 本仓仅有离线维护脚本适配，不存在 Hub 注册模块 | **已完成（Hub 边界）**；Hub 无 S3 模块，跨仓多存储 + MinIO S3 已完成（管理员按库指定存储方案，自助选择 UI 未完成） |
| `CF_ENABLE_EXTERNAL_SOURCES` | 新应用扩展 | Seahub 列表/文件 API 外形 | local-path provider、授权、只读浏览/下载、overlay、shadow API、Meilisearch 扫描 | **部分完成**；72 个相关测试通过；当前 `local-path` 为只读内容入口，真实 SMB/NFS 挂载、数据库与浏览器流程待验收 |

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
