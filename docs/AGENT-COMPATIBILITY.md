# Agent 服务端兼容边界

2026-10-13 按当前路由注册及公开设备契约整理。源码接线、安装包能力与真实桌面验收分别判断，本文不宣布新的产品发布。

| 路径族 | 用途 | 兼容边界 |
| --- | --- | --- |
| `api/v2.1/cloudfile/repos/{repo_id}/local-sessions/` 与 `agent-sessions/claim/` | legacy 浏览器一次性会话交接 | 普通查看/编辑副本；不从这个入口创建独占编辑，也不使用旧文档的 content/heartbeat 回写路径 |
| `api/v2.1/cloudfile/extensions/local-edit/` | 当前设备、读取、普通/独占本地编辑会话及设备签名上传 | `CLOUDFILE_LOCAL_EDIT_ENABLED` 门控；操作依设备与会话授权，不以语言选择权限 |
| `api/v2.1/cloudfile/extensions/editing/v1/` | status、checkout、heartbeat、resume、abandon、cancel、checkin、commit-file | `CLOUDFILE_EDITING_ENABLED` 门控；复用统一 Editing Service 与服务端条件发布 |

`local-edit` 和 `editing` 是保留域，客户扩展不得覆盖。二者可同时装配；设备会话票据、读取 ticket、上传凭据和用户/OIDC 认证不能互换。claim/prepare 成功不等于文件已发布，只有匹配原 Intent 的持久 published 回执才能表明提交成功。

Windows 组合包使用单一 .NET Native Host 与内部 Go Core，macOS 使用 Go Host。平台界面与本地密钥处理可以不同，服务端文件权限、租约、基线和提交回执规则保持一致。Go Core 版本不等于 Windows 整包版本。

设备上传、原 Intent 恢复和当前客户端边界见 [设备上传契约](https://github.com/eaopen/cloudfile-local-agent/blob/dev/docs/device-upload-contract.md)，macOS 见 [平台说明](https://github.com/eaopen/cloudfile-local-agent/blob/dev/docs/macos.md)。完整浏览器、设备、Office/CAD、服务端及异常恢复仍须按实际发行包验收。

路由依据：[根路由](../cloudfile_extensions/root_urls.py)、[local-edit 路由](../cloudfile_extensions/local_edit/urls.py)、[editing 路由](../cloudfile_extensions/editing/routes.py)、[共存回归](../cloudfile_extensions/tests/test_routing.py)。升级已有数据库须先核对所选版本迁移说明，不能沿用早期“只验新建库”的开发结论替代升级步骤。
