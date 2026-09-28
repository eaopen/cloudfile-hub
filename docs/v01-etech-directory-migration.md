# v0.1 eTech 组织映射迁移

沿用 v0.1 的全量 `/eap/cloudDrive/directory/groups` 快照、父先子后的群组创建、成员差异对账，以及空快照和大批量撤员拒绝规则。`org_user.id_`、`org_group.id_`、`org_role.id_` 是唯一映射键；角色快照中的 `role:<id>` 写入当前 `namespace=role, external_id=<id>`，部门写入 `namespace=directory`。不按名称或邮箱猜测映射。

从真实 v0.1 数据库升级时，先备份数据库并停掉旧目录 worker 与 CloudFile 写入，再在旧 `cf_sso_group_map` 所在的策略数据库执行：

```sh
python3 -m cloudfile_extensions.directory.legacy_migration --native-schema ccnet_db
```

该命令使用现有 `CLOUDFILE_DB_*` 连接配置，校验旧映射、父子关系和原生 `group_id`，将行转换到当前表形态；旧表保留为 `cf_sso_group_map_v01backup`。不支持的旧记录会拒绝迁移，不能自动按群组名归并。随后运行当前 CloudFile schema migration，配置 `CF_SSO_GROUP_OWNER` 为一个已有且启用的 Seafile 账号；大批量撤员护栏沿用 `CF_SSO_MAX_REMOVAL_RATIO`（默认 0.5）。启动服务后，通过 eTech 管理页执行一次目录同步并检查返回 `status=OK`、`unresolved_count` 和 `quarantined_groups`。周期同步使用 eTech PowerJob handler `cloudDirectorySync`，沿用 v0.1 的 600 秒周期。

已迁移到当前表结构的新库不运行旧表命令。`cf_sso_group_map_v01backup` 在核对授权和原生群组 ID 后由运维按数据库备份策略处理；同步任务不会删除原生群组。
