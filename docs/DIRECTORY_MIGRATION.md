# 旧目录映射迁移

本文只说明代码中的迁移工具边界，具体业务目录字段、客户周期任务和发布记录由客户私有工程维护。

旧 `cf_sso_group_map` 表迁移工具为 `cloudfile_extensions.directory.legacy_migration`。在备份、停写并停止旧目录 worker 后，先核对所选版本支持的旧表形态，再执行该版本迁移说明；不要在已迁移的新表上重复执行旧表迁移。

```sh
python3 -m cloudfile_extensions.directory.legacy_migration --native-schema ccnet_db
```

命令读取 `CLOUDFILE_DB_*` 连接配置，校验旧映射、父子关系和原生群组 ID。不支持的旧记录应停止处理，不按名称或邮箱猜测身份。迁移前后核对备份表、目标映射、库授权及目录同步拒绝行为；完整步骤须匹配原版本和目标版本，不能仅凭命令正常退出宣布业务升级完成。

参见 [Hub 配置](CONFIGURATION.md) 与 [测试说明](TESTING.md)。
