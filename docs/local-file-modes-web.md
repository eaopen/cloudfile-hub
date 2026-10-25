# 库级 Checkout 与 Hub 网页本地文件入口

产品决策（2026-10-25）：CloudFile 只支持两种库级策略——**OFF（默认）** 与 **OPTIONAL（Repo UUID 白名单）**；**不提供 REQUIRED**，不按扩展名自动 Checkout，不增加新表。Hub 以 [#87](https://github.com/eaopen/cloudfile-hub/pull/87) 的按库能力判断为前提。

关联：[Agent2 #10](https://github.com/eaopen/cloudfile-local-agent2/issues/10)、[总验收 #1](https://github.com/eaopen/cloudfile-local-agent2/issues/1)。本文仅记录网页接线；真实联动未通过前，两项 Issue 保持 Open。

## 入口及权限规则

文件列表选择一个文件后点击“本地文件操作”；文件预览页从更多操作进入同一窗口。窗口显式列出本地查看、普通编辑、独占编辑，不根据文件扩展名自动选模式。

| 当前状态 | 本地查看 | 普通编辑 | 独占编辑 / 恢复 |
| --- | --- | --- | --- |
| 文件有效权限 `r` | 允许 | 禁用 | 禁用 |
| 文件有效权限 `rw`，资料库可写，**OFF 库** | 允许 | 允许 | 禁用（不查询 Guard） |
| **OPTIONAL 库**，Guard 健康且无占用 | 允许 | 允许 | 允许 |
| **OPTIONAL 库**，Guard 不可用 / 查询失败 / 状态未知 | 有读权限时允许 | 禁用（锁状态无法确认） | 禁用 |
| **OPTIONAL 库**，已被**本人**占用 | 允许 | 禁用新普通任务 | 允许“继续独占编辑”：复用 `open` 接口领取 `exclusive-edit` 票据，Agent2 验证原 Guard 后恢复任务 |
| **OPTIONAL 库**，已被**他人**占用 | 允许 | 禁用新任务 | 禁用新任务；引导已有 Agent2 任务 |
| 资料库只读 | 有读权限时允许 | 禁用 | 禁用 |
| 无读权限 | 禁用 | 禁用 | 禁用 |

文件列表优先使用条目的有效 `permission`，未提供时使用当前目录 `userPerm`。界面权限仅提示，不能代替 Hub `Authority` 签票及原生 Server 每次读写/Checkout 的终判；占用与撤权竞态由服务端拒绝。

## 协议及失败处理

三种模式均复用 `openV2LocalFile` → 当前登录用户的 `POST /api/v2.1/cloudfile/edit/v1/open/` → 同源 `cloudfile-open://v2/open` → 已有 Chrome `open_uri` → Agent2；无新接口、新表、新票据格式及 Host。

- 本地查看不写回；普通编辑保存后自动发布；独占编辑在 Agent2 中人工 Commit/Checkin，本机保存不代表云端发布已确认。
- 打开窗口时读取一次路径级 `lock-info`，不轮询。`checked_out_by_me` 只用于区分本人/他人；本人“继续独占编辑”仍复用同一 `open` 接口签票，最终由 Agent2 校验原 Guard，Hub/Server 不代做恢复判断。
- `lock-info` 返回未知（503/网络失败）时按“锁状态无法确认”处理：禁用新的普通/独占任务，本地查看可用；不得把未知当成“没有锁”。
- HTTP 拒绝、模式不匹配、插件缺失或响应未知均不自动重试、不降级 V1、不改为普通编辑、不跳转下载或绕过授权上传。错误保留在窗口，未知结果先查 Agent2 任务中心。
- Checkout 不支持（OFF 库）时允许用户另行显式选择普通编辑；它不是失败后的自动回退。

## 核验范围

检查基线：Hub 最新 `dev`（含 #86）+ 前置 #87、Chrome 扩展 `0a66287`、Agent2 `3daea00`。本次只修改 Hub。

已运行：Hub 三组定向 Jest（窗口模式/权限/Guard 未知/本人恢复/他人占用/拒绝/防重入、文件列表有效权限与回调接线、V2 模式转发与无降级）；Chrome `node --test tests/open-uri.cjs tests/agent2-routing.cjs` 共 19 项；`git diff --check` 与 `test_no_managed_boundary.py`。

Hub 在完整前端依赖已安装的环境可运行：

```sh
cd frontend
CI=true npm test -- --watchAll=false --runInBand src/cloudfile/__tests__/agent-local-edit.test.js src/components/local-file-dialog/__tests__/index.test.js src/features/library-view/toolbar/selected-dirents-toolbar/__tests__/local-file.test.js
```

视觉截图尚未取得：本地浏览器运行时缺失，下载返回损坏的 ZIP；不将 jsdom 验证视为真实浏览器截图或实机验收。

本轮 Jest 使用隔离测试依赖和 Babel 转换（无仓库依赖/锁文件修改），没有运行 Seahub 全量构建、Django 集成、镜像构建或 Rust 全量测试。

依赖方向说明：共享窗口沿用现有文件预览页对 `src/cloudfile` 协议/API 的访问，不把页面状态移入 API，也不新增反向依赖。`src/cloudfile` 当前未在前端分层表中单列；后续如统一迁移到 `api`/`features`，应整体迁移现有调用，本次不扩大目录重构。

## 待验收（不得以 Mock/CI 勾选）

- [ ] Windows + macOS 标准用户，真实 Chrome → 已登录 Hub → Rust Agent2，排除旧 Host 接管。
- [ ] 只读票据真正打开，禁止上传/Checkout/Checkin；撤权、过期票据拒绝。
- [ ] Office 普通编辑保存形成原生 File ID/Branch/版本并在网页可见；冲突和离线保留副本。
- [ ] 两账号同文件独占互斥；Commit 保留 Guard、Checkin 释放；续租、撤权及未知回执恢复。
- [ ] 完整 DEV 记录 Hub/Server/Chrome/Agent2 SHA、账号权限、网络入口及原生版本/Guard 事实，反链到 #1/#10。

未经上述真实验收不推 PROD；本 PR 不关闭 #1/#10。
