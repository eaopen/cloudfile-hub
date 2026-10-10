# V05-01 单实例容量与健康诊断（开发增量）

管理员在已经正确配置 Seafile CE 数据库的 Hub 环境中运行：

```bash
python3 manage.py cf_capacity_report --limit 100 --offset 0
```

输出单行 JSON，`schema=cloudfile.capacity.v1`、UTC 采集时间、`build_version`（可选 `CF_BUILD_VERSION`，否则 unknown）、分页信息、库总数和库 ID。每个库存储大小采用 Seafile `RepoSize.size`（逻辑大小）；文件计数采用 `RepoFileCount.file_count` 缓存。对应行缺失时明确 `status=unknown`，绝不冒充 0；目录数及搜索索引 backlog 暂时 `unsupported`。后台任务 backlog 在 `cf_background_job` 运行表可用时按已索引的 status 统计 queued/running/failed；表不存在/无法访问时显式标记不支持并记录可用性错误。磁盘剩余空间仅在可信 `settings.SEAFILE_DATA_DIR` 可访问时读取，否则明确 unknown。

仅由服务端管理员命令发起，无 Web/API 公共入口，不递归遍历文件、不读取文件体、不修改业务数据，限制每页 1–1000 库。数据库名来自既有 `SeafileDB` 配置，并严格校验为合法 identifier；数据库访问失败保守报错，不提供错误堆栈或凭据。具体库/文件真实数量仍依赖 Seafile CE 已维护的统计表新鲜度，不代表容量 SLA、文件版本总量或物理去重块大小。

本地回归：`python3 -m unittest discover -s tests -p test_cf_capacity_report.py -v`，3 项通过，使用受控模拟数据库 cursor。**尚未在真实 Seafile 数据库运行该命令**，本轮不声明百万规模支持，也不将 unsupported 指标当作已交付统计。
