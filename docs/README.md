# CloudFile Hub 文档索引

产品定位、公开路线与 AI 方向统一见 [CloudFile 产品文档](https://github.com/eaopen/cloudfile/blob/main/docs/README.md)。本仓维护随代码更新的技术参考；内部研发复盘与客户部署记录不在这里维护。

> 用途：区分当前有效文档、跨仓权威文档和上游随代码保留的历史资料。
> 适用版本：Seafile CE 14.x。
> 状态：文档导航；能力成熟度以对应技术说明和所选发行版本为准。

## 当前有效文档

| 文档 | 内容 | 状态 |
|---|---|---|
| [架构](ARCHITECTURE.md) | Hub 分层、注册生命周期、请求与数据流 | 技术参考 |
| [扩展注册中心](EXTENSIONS.md) | 链式扩展点、可选 provider、后台任务 | 技术参考 |
| [能力矩阵](CAPABILITIES.md) | CE 复用、本项目新增、外部依赖和逐项交付状态 | 技术参考 |
| [Hub API](API.md) | CloudFile 路由、方法、认证、开关和已知限制 | 技术参考 |
| [Hub 配置](CONFIGURATION.md) | 本仓读取的功能开关、provider 与运行参数 | 技术参考 |
| [测试与证据](TESTING.md) | 测试命令、覆盖边界、CI 与本次验证结果 | 技术参考 |
| [本地专业软件](local-professional-software.md) | `.cloudfile` 会话、本地查看/编辑和签出边界 | 部分完成 |

## 跨仓权威文档

下列主题不在本仓复制维护，避免三份说明漂移：

- 部署、镜像、环境变量生成：`cloudfile-docker/deploy/compose/`。
- 跨仓能力总表与上游策略：`cloudfile-docker/docs/feature-matrix.md`、`upstream-contribution.md`。
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

内部旧方案与复盘归入内部管理仓库；公开的版本化技术说明按适用版本保存并注明替代入口，不作为当前能力证明。

## 运维与集成技术参考

| 文档 | 适用范围 |
| --- | --- |
| [资源集成与运行配置](../CLOUDFILE.md) | 扩展运行时技术参考，配置示例按部署调整 |
| [文件补索引](SEARCH_FILE_BACKFILL.md)、[目录补索引](SEARCH_DIRECTORY_REPAIR.md) | legacy 索引的受控补全 |
| [索引对账](SEARCH_RECONCILE.md) | 只读覆盖率和陈旧文档诊断，不替代权限验收 |
| [旧目录映射迁移](DIRECTORY_MIGRATION.md) | 版本化旧表工具与停写边界 |
| [Agent 兼容](AGENT-COMPATIBILITY.md) | legacy 会话、设备认证与受控编辑边界 |

上游保留资料：[旧发布脚本说明](../scripts/server-release.md)、[头像旧迁移](../seahub/avatar/sql/migration.md)、[第三方许可](../thirdpart/shibboleth/license.md)。前两项只适用于原上游版本，第三方许可持续保留。
