<!-- generated-by: gsd-doc-writer -->
# CloudFile Hub

> 用途：说明 CloudFile 的 Web/API 仓库定位、边界和最短验证路径。
> 适用版本：Seafile CE 14.x；当前基线来自 `haiwen/seahub`。
> 状态：已完成（文档与 `dev` 分支代码核对，2026-08-11）。

CloudFile Hub 是 Seahub 的长期跟随型 fork：复用 Seafile CE 14 的 Web、API、认证与文件预览能力，在 `cloudfile_ext/` 和 `frontend/src/cloudfile/` 中补充 Pro 平替、CE 补强和新应用扩展。

## 产品边界

| 边界 | 当前做法 |
|---|---|
| CE 复用 | 登录认证、库/目录/文件基础 API、权限基线、原生预览、SeaSearch/Elasticsearch 路径 |
| 本项目新增 | 扩展注册中心、目录 ACL、组织映射、操作审计、Meilisearch、外部文件源、统一文件动作与本地软件会话 |
| 外部组件 | `cloudfile-server` 负责不可绕过的底层权限/锁校验；`cloudfile-docker` 负责构建、配置、数据库建表和部署；Meilisearch、IdP、客户目录服务和挂载目录由部署侧提供 |

本仓库不是独立可部署产品。完整运行需要三个仓库并排检出：

```text
workspace/
├── cloudfile-server/
├── cloudfile-hub/
└── cloudfile-docker/
```

部署入口与跨仓规格以 `cloudfile-docker` 为准；本仓文档只描述 Hub/Web/API 的真实实现。

## 当前状态

- 扩展框架与 `CF_ENABLE_*` 默认关闭语义已完成；关闭全部开关时应保持原生 CE 行为。
- Hub 扩展测试当前为 `217 passed`；这不等同于三仓集成或部署验收。
- 目录 ACL、搜索、外部源、SSO 组织映射、审计和文件动作已有代码；逐项状态与缺口见 [能力矩阵](docs/CAPABILITIES.md)。
- CloudFile 自有 `metadata`/标签扩展仍是占位，但 CE 已有 `repo_metadata`、`repo_tags`/`file_tags` 前端和 API；跨仓部署已验证标签定义生命周期，目录/文件绑定闭环仍未验收。转换导出与监控也不应按“已验收”宣传。

## 最短验证

```bash
.venv/bin/python -m pytest cloudfile_ext/ -q
```

三仓并排且依赖就绪时运行统一门禁：

```bash
../cloudfile-docker/tools/run-checks.sh
```

## 文档入口

- [文档索引](docs/README.md)
- [架构](docs/ARCHITECTURE.md)
- [扩展注册中心](docs/EXTENSIONS.md)
- [能力矩阵](docs/CAPABILITIES.md)
- [Hub API](docs/API.md)
- [Hub 配置](docs/CONFIGURATION.md)
- [测试与证据](docs/TESTING.md)
- [本地专业软件](docs/local-professional-software.md)

开发约束见 [AGENTS.md](AGENTS.md)。
