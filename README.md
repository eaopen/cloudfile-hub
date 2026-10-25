[CloudFile product home / 产品总入口](https://github.com/eaopen/cloudfile) · [English](https://github.com/eaopen/cloudfile/blob/main/README.md) · [简体中文](https://github.com/eaopen/cloudfile/blob/main/README.zh-CN.md)

# CloudFile Hub

> **当前开发：GitHub 默认 `dev` = CloudFile V2**（基于 Seafile CE14）。不是旧 V0.x 或已归档的 `dev2`。功能分支用 `feat/<功能>`，修复分支用 `fix/<问题>`，文档分支用 `docs/<主题>`；无需版本前缀。

CloudFile Hub is the Web/API layer built on the Seahub Community Edition source. It works with [CloudFile Server](https://github.com/eaopen/cloudfile-server) for data-plane authorization and [CloudFile Docker](https://github.com/eaopen/cloudfile-docker) for source assembly and deployment.

CloudFile Hub 基于 Seahub CE14，负责 Web/API、身份与企业集成接口、文件与目录展示、可选搜索等。V2 尽量复用 Seafile 原生功能；ACL、Tag、Checkout 等内置能力遵循当前 V2 实现，**不再按旧 V0.x 文档要求添加一套可选开关**。

## 当前开发边界

- 日常任务一律以三仓 `dev` 的 V2 设计与源码为准，历史旧版资料仅供追溯。
- 涉及 Server/Hub/Docker 的变更，联验与发布时记录确切的三仓 Commit SHA；分支同名不保证运行兼容。
- 源码已提交、镜像已构建、DEV 已部署、客户业务已验收是不同事实，不得互相代替。
- 只需修改文档时不编译、不测试；修改代码时按实际影响做定向验证，完整编译/镜像/E2E 在明确的集成或发布阶段按需执行。
- 当前 V2 源码约束以 [AGENTS.md](AGENTS.md) 为准；根目录 [CLOUDFILE.md](CLOUDFILE.md) 属于 V0.x 历史设计，不是现行构建或授权指南。

## 文档入口

- [Hub 文档索引](docs/README.md)
- [V2 分支统一规范](https://github.com/eaopen/cloudfile-docker/blob/dev/BRANCHING.md)
- [Hub API 参考](docs/API.md)
- [Hub 代码能力和证据（须核对记录日期）](docs/CAPABILITIES.md)
- [Hub 测试与证据](docs/TESTING.md)

上游 Seahub 文档与代码可以作为实现参考，但不能用上游分支或历史扩展版取代 CloudFile V2 `dev`。
