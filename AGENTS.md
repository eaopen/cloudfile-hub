# AGENTS.md — cloudfile-hub

> **当前规则**：`cloudfile-hub/dev` 是 **CloudFile V2 当前开发主线**，基于 Seafile CE14。`dev` 不是旧 V0.x、`dev2`、`dev2-clean` 或上游 Seahub 的替身。本文件是本仓 AI coding Agent 与维护者的现行开发约束。

## 统一分支

| 分支 | 用途 |
| --- | --- |
| `dev` | 唯一当前开发主线（V2） |
| `feat/<功能>` | 新功能 |
| `fix/<问题>` | Bug 修复 |
| `docs/<主题>` | 文档更新 |
| `archive/<历史名称>` | 历史只读快照 |

新工作从 `dev` 派生，不再叠加 `v2/`、版本号、日期或任务编号等强制层级。不要重建 `dev2` / `dev3`。已有 `feature/*`、`fix/v2-*` 等在途分支按原任务处理即可，无需中途批量更名。历史 V0.x 模块、配置、测试和文档不能因出现在当前 Git 树就视为 V2 开发合同；禁止整枝合并旧开发分支。

跨仓功能只有涉及的仓库才建立同名工作分支；真正可运行的组合取决于 **Server / Hub / Docker 三仓的固定 Commit SHA**。权威分支规则见 [CloudFile Docker BRANCHING.md](https://github.com/eaopen/cloudfile-docker/blob/dev/BRANCHING.md)。

## 本仓职责与安全底线

本仓是 `haiwen/seahub` 的 fork，负责 Web、API、SSO/OIDC、目录与文件展示、搜索及 V2 权限接口；Server 负责不可绕过的文件访问和写入终判，Docker 负责跨仓构建和部署。

- **当前实现以 `cloudfile_ext/v2/`、原生 CE14 的真实执行入口及当前代码/契约为准。** `cloudfile_extensions/`、旧 `cloudfile_ext/*`、`CLOUDFILE.md` 里的 V0.x 内容可能是历史/兼容实现，不能直接复制旧架构和旧任务表。
- 目录 ACL、原生 Tag、Checkout 等已成为 V2 内置能力时，不要重新添加旧 `CF_ENABLE_*` / `v2_acl_enabled` 开关。外部 Meilisearch、OIDC 等保留必要连接配置与真实可用性判断，不另造功能启用体系。
- 不依靠隐藏按钮或“返回 HTTP 200”代表授权；目录展示和实际读取/上传/提交必须使用相应的 V2 权限校验与 Server 终判。受保护的入口出现错误时不得退回宽松的旧路径。
- 新增功能优先放 CloudFile 独立目录；修改上游 Seahub 文件须证明必要性，并核对 Docker 仓的 [上游改动清单](https://github.com/eaopen/cloudfile-docker/tree/dev/docs/upstream-patches)。
- Etech 等业务定制属于消费者，不把客户专用业务逻辑固化在通用 Hub。未经确认不要顺手增加表、API、兼容层或扩大开发范围。

## 只做必要验证

**纯文档修改无需编译、运行测试或构建镜像。** 普通代码修改根据本次受影响的模块进行定向检查；不要求每次都跑全量 `pytest`、Seahub 构建、三仓镜像或 E2E。影响登录、权限、读写字节与跨仓契约时选择相应专项验证；完整编译/联验留给确有必要的集成和发布节点。没有实测过的 DEV/Etech 流程不得宣称已通过。

检查与具体 API 契约以当前 V2 代码为准；参考 [docs/README.md](docs/README.md) 及 Docker 当前分支和源码组合规则。上游 `frontend/AGENTS.md`、`seahub/AGENTS.md` 的代码风格要求仍适用于相应目录，但不能覆盖本文件的产品版本与分支规则。

## 约定

保持代码、注释和 commit message 英文，文档用中文；不提交构建产物、`node_modules/`、`__pycache__/`、凭据或本地临时文件。保留原生 CE 行为和兼容性时，以当前调用点与证据核对，不凭旧文档推断。

## 当前数据库（未正式发布 V2）

- 唯一扩展表为 `cf_library_storage`、`cf_dir_acl`、`cf_sso_group_map`、`cf_edit_guard`、`cf_audit_event`；新装一次创建全部五表，已有卷只校验。
- 不迁移或追溯开发期旧数据。存储绑定从 Seafile 的 Repo/RepoStorageId 重新识别，ACL/共享和组织/角色从 Etech 重新同步，Guard/审计从空表开始；旧 `cf_tag`、Resource、Intent、Session、Outbox 不恢复。
- 绝不清除 CE 原生 Repo、Branch、文件内容、版本或原生 Tag，也不因为缺表自动建立旧扩展 DDL、迁移服务或产品级升级框架。

## 本地查看/编辑（V2 运行合同）

- Web 入口统一使用 `POST /api/v2.1/cloudfile/edit/v1/open/`，`mode` 仅 `local-view`、`optimistic-edit`、`exclusive-edit`；受信 Chrome 插件交给 Agent2 `cloudfile-open://v2/open`。
- Server Go `/cf-edit/v1/*` 负责最终权限、内容 CAS 与独占 Guard。仅 `cf_edit_guard` 持久化独占状态；本机编辑任务/待提交状态归 Agent2 Journal。
- **不得恢复** `cf_edit_session`、`cf_resource`、`cf_commit_intent`、旧设备/会话/回执表，也不得让旧 `extensions/local-edit/v1/*` / `file_actions.local-sessions` 重新参与运行。
- 本地普通编辑无需 Checkout；独占编辑按 Guard 及实际启用能力返回。出现 `cf_edit_session doesn't exist` 是旧调用或旧部署证据，禁止以补表修复。

## 仅允许当前五张扩展表

- 当前 V2 数据模型：`cf_library_storage`、`cf_sso_group_map`、`cf_dir_acl`、`cf_edit_guard`、`cf_audit_event`。Tag 属于 CE 原生表，文件版本/动作使用 CE Commit/Activity。
- `cloudfile_extensions/schema/migrations` 的旧 001–042 迁移链已移除；不得从历史 Git 分支复制回来，也不得注册 `cloudfile_extensions.*` 旧 URLConf 或启动旧 PolicyHost/Worker。
- 当前 URI/Agent2 编辑流程不使用 SQL Session、Resource、Intent，历史编辑服务可能还出现在 Git 树中以便追溯，但不属于当前运行或发布合同。

## 现行 V2 权限契约：禁止“托管库”复活（2026-10-21）

- `dev` **不存在托管库/非托管库两种类别**。任何 `cf_dir_acl` 行只代表其目标路径和主体的显式规则，不能被用于判定整库被托管、整库访问关闭、旧入口一律拒绝或重新进入单独的库级安全模式。
- 唯一权限链：Seafile CE 原生库资格 + Hub `Authority.effective()` 对当前身份和实际路径的 ACL/共享目录结果 + C/Go 真实文件与最终 Commit 终判。无整库资格但有 `share_mode=true` 的用户只从共享目录根进入，不得开放库根、父级或兄弟目录。
- **坚决禁止**恢复 `cf_managed_library`、`cf_managed_library_share`、`cf_library_share_revision`、`checkLegacyLibrary`、`cf_policy_check_legacy_library`、`managed_library_guard`、`allow_legacy_managed_reads`，也禁止恢复用于断言“库有任意 ACL 行就应全库拒绝”的测试。
- 没有可信当前用户/路径的整库同步或无范围票据，允许因该**操作缺乏授权证明**而拒绝；这不是库分类。任何有路径证明的 Web/API/Agent/下载/上传必须按实际目标裁决，不能用无关目录的 ACL 拒绝整个库。策略异常不回退宽权限。
- 当前文档与测试应以 V2 权限终判契约及五张扩展表为准；历史文档只用于追溯，不得作为实施依据。跨仓变更必须维护防复活的源码扫描和正反权限用例。
