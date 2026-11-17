# 资料库能力管理

库管理员权限由 Seahub 的原生站点管理身份和 can_manage_library 校验。
单库 GET /api/v2.1/admin/cloudfile/repos/{uuid}/features/ 返回 repo_id、
已配置的 features 数组，以及 checkout、protection 各自的 configured 和 runtime。
原生库不存在、缺少 master 或为虚拟库时返回 404。批量库存核对仍走 storage/reconcile。

Hub 复用 Seahub 现有内部 Fileserver 地址、端口和 JWT 密钥。标准 CE 单机部署无需增加配置。
Hub 在管理查询和启用时探测 Go Fileserver、它连接的 C 服务及相关 Schema。
单机本地回环地址的探测通过时返回 ready，已发现缺少能力时返回 unavailable。
旧服务、连接失败或响应不完整时返回 unknown。原生集群模式和非回环地址只能观测一个
响应实例，探测通过仍返回 unknown，因此这些拓扑暂不支持通过此接口新增启用。

POST 到同一路径，仅提交需要改变的布尔字段。新增启用要求该项 ready，否则整批返回
503。已保护文件或活动签出租约阻止对应关闭，整批返回 409。实际状态变更和
cf_audit_event 审计行在同一 Branch 事务内提交。重复提交相同状态不会重复记账。
部署顺序为 Server、Hub、Etech 后端。Etech 管理页只读。

例如，protection 已配置但原生服务暂时失联时，详情仍可区分配置和运行状态：

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
