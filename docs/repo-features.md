# 资料库能力管理

库管理员权限由 Seahub 的原生站点管理身份和 can_manage_library 校验。
单库 GET /api/v2.1/admin/cloudfile/repos/{uuid}/features/ 返回 repo_id、
已配置的 features 数组，以及 checkout、protection 各自的 configured 和 runtime。
原生库不存在、缺少 master 或为虚拟库时返回 404。批量库存核对仍走 storage/reconcile。

在 seahub_settings.py 中声明**所有**写入实例的 Fileserver 内部直连地址。
每个地址应对应一个 Go 进程及其实际使用的 C RPC 服务。例如单节点部署：

    CLOUDFILE_WRITER_ROOTS = ['http://127.0.0.1:8082']

多节点应逐项列出，不能填负载均衡地址；节点增减须同步清单。Hub 使用既有 JWT 密钥签发
短效专用票据。每次管理查询或启用操作检查当前进程、原生 RPC 版本和 Schema。
全部实例通过才返回 ready；已知任一实例缺少能力时返回 unavailable；未声明清单、
旧版本或无法完成核验时返回 unknown。运行状态是请求时的观测值。

POST 到同一路径，仅提交需要改变的布尔字段。新增启用要求该项 ready，否则整批返回
503。已保护文件或活动签出租约阻止对应关闭，整批返回 409。实际状态变更和
cf_audit_event 审计行在同一 Branch 事务内提交。重复提交相同状态不会重复记账。
部署顺序为 Server、带完整实例清单的 Hub、Etech 后端。Etech 管理页只读。

例如，protection 已配置但有实例暂时失联时，详情仍可区分配置和运行状态：

```json
{
  "repo_id": "00000000-0000-4000-8000-000000000001",
  "features": ["protection"],
  "capabilities": {
    "checkout": {"configured": false, "runtime": "unknown"},
    "protection": {"configured": true, "runtime": "unknown"}
  }
}
```
