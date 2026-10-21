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

## 开发期数据库变更（2026-10-21）

- 新版当前只明确新增四张业务表：`cf_library_storage`、`cf_dir_acl`、`cf_sso_group_map`、`cf_edit_guard`。历史表仅作备份或迁移输入，不属于新版运行库及运行依赖；增加业务表须先确认，历史数据单独归档，不直接删除。
- 开发期建表、升级及数据迁移通过 Docker 仓 `database/` 下独立、人工执行的 SQL 交付，DEV 验证与 PROD 发布复用固定脚本及校验和。启动/重启仅校验，不自动执行扩展 DDL、旧迁移链或兼容补丁。
- 仅明确审核的成熟版本之间才考虑自动升级；须定义精确源/目标范围和数据/中断恢复验证。不得根据 dev 分支、表名存在或旧台账自动推断升级路径，不自动回滚。

## 本地查看/编辑（V2 运行合同）

- Web 入口统一使用 `POST /api/v2.1/cloudfile/edit/v1/open/`，`mode` 仅 `local-view`、`optimistic-edit`、`exclusive-edit`；受信 Chrome 插件交给 Agent2 `cloudfile-open://v2/open`。
- Server Go `/cf-edit/v1/*` 负责最终权限、内容 CAS 与独占 Guard。仅 `cf_edit_guard` 持久化独占状态；本机编辑任务/待提交状态归 Agent2 Journal。
- **不得恢复** `cf_edit_session`、`cf_resource`、`cf_commit_intent`、旧设备/会话/回执表，也不得让旧 `extensions/local-edit/v1/*` / `file_actions.local-sessions` 重新参与运行。
- 本地普通编辑无需 Checkout；独占编辑按 Guard 及实际启用能力返回。出现 `cf_edit_session doesn't exist` 是旧调用或旧部署证据，禁止以补表修复。
