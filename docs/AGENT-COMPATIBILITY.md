# Agent 与 Agent2 服务端兼容边界

更新：2026-09-30。当前 .NET Agent 完成已承诺功能和首发验收后进入维护；Agent2（Go）先覆盖基础能力，再承接 v0.6 回写。两者接入同一 Hub/Server，不按语言创建独立业务后端。完整路线见 [统一契约](../../eap-cloudfile/docs/features/agent-server-contract-evolution.md)。

| 消费者 | 保留的服务端契约 | 当前边界 |
| --- | --- | --- |
| 当前 Agent（.NET） | `local-edit/v1/agent/` 的 challenge、claim、read-challenge/read-ticket、renew-challenge/renew、cancel-challenge/cancel；受管 `/seafhttp/cloudfile/read` 下载 | 配对与设备证明不变；view/optimistic-edit、Web 手动上传；不新增 exclusive-edit 或受控回写 |
| Agent2（Go）编辑适配资产 | `editing/v1/` 的 status、checkout、heartbeat、resume、abandon、cancel、checkin、commit-file | 已有人工提交、持久意图与恢复适配；要求受信认证 client，设备 broker 与 CLI/浏览器接线尚未完成 |

两组路由按能力独立门控，可同时装配。.NET local-edit 会话票据不授予 Editing Service 上传权限；同一用户的会话完成状态 `completed` 与提交意图的 `published` 分属不同状态域。Go 适配不通过普通上传覆盖接口替代原生条件发布，也不以客户端提交的用户名/语言取得权限。

`editing` 和 `local-edit` 均为保留域，项目 URLConf 或能力注册不得覆盖它们。未启用 `CLOUDFILE_EDITING_ENABLED` 时没有公开编辑路由；开启编辑不能替换 .NET 的设备/read-ticket 路由。路由共存、默认关闭和认证拒绝行为由 [路由回归](../cloudfile_extensions/tests/test_routing.py)覆盖。

本次合并按未上线范围处理：只验收新建隔离数据库的 `029_editing_core`，不恢复旧 `029_lock_leases` 或提供历史数据迁移。旧测试库保持拒绝未知迁移，不自动清账或重建，也不修改现有部署数据。

合并开发源码不等于启用编辑或发布新制品。`CLOUDFILE_EDITING_ENABLED`、FILE_LOCK、CHECKOUT 继续默认关闭；Windows CNG/ACL/安装和 Office/CAD 实机验收、Agent2 完整身份链仍单列，不由路由与库测试代替。
