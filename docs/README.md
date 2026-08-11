<!-- generated-by: gsd-doc-writer -->
# CloudFile Hub 文档索引

> 用途：区分当前有效文档、跨仓权威文档和上游随代码保留的历史资料。
> 适用版本：Seafile CE 14.x。
> 状态：已完成（2026-08-11）。

## 当前有效文档

| 文档 | 内容 | 状态 |
|---|---|---|
| [架构](ARCHITECTURE.md) | Hub 分层、注册生命周期、请求与数据流 | 已完成 |
| [扩展注册中心](EXTENSIONS.md) | 链式扩展点、可选 provider、后台任务 | 已完成 |
| [能力矩阵](CAPABILITIES.md) | CE 复用、本项目新增、外部依赖和逐项交付状态 | 已完成 |
| [Hub API](API.md) | CloudFile 路由、方法、认证、开关和已知限制 | 已完成 |
| [Hub 配置](CONFIGURATION.md) | 本仓读取的功能开关、provider 与运行参数 | 已完成 |
| [测试与证据](TESTING.md) | 测试命令、覆盖边界、CI 与本次验证结果 | 已完成 |
| [本地专业软件](local-professional-software.md) | `.cloudfile` 会话、本地查看/编辑和签出边界 | 部分完成 |

## 跨仓权威文档

下列主题不在本仓复制维护，避免三份说明漂移：

- 部署、镜像、环境变量生成：`cloudfile-docker/deploy/compose/`。
- 跨仓能力总表、产品定位与上游策略：`cloudfile-docker/docs/feature-matrix.md`、`upstream-contribution.md`。
- 目录 ACL、搜索、外部源、SSO、存储的完整规格：`cloudfile-docker/docs/` 对应专题。
- 上游兼容补丁登记与 PR 总表：`cloudfile-docker/docs/upstream-patches/` 及其上层索引。
- C/Go 强制校验与数据库 DDL：`cloudfile-server/`。

## 仓内其他 Markdown

这些文件不是当前 CloudFile 产品说明，不纳入能力状态：

| 路径 | 性质 | 处理 |
|---|---|---|
| `AGENTS.md`、`CLAUDE.md` | 仓库协作约束 | 保留在根目录；以 `AGENTS.md` 为唯一规则来源 |
| `scripts/server-release.md` | 上游旧版打包记录 | 保留原路径以减少上游同步冲突；不作为 CE 14 发布指南 |
| `seahub/avatar/sql/migration.md` | 上游 6.2 头像迁移记录 | 保留原路径；不作为 CE 14 通用迁移步骤 |
| `sql/README.md` | 上游 Seahub schema 维护说明 | 随上游保留 |
| `thirdpart/shibboleth/license.md` | 第三方许可证 | 原样保留，不改写、不归档 |

旧方案若曾被 CloudFile 当前文档引用，迁入 `docs/history/` 后必须在本索引注明替代文档；不得把历史方案继续写成当前能力。
