# 原生存储登记预检

`origin/dev` 基线：`ee732e74ce02f184586e1313b489e2198dbc15fe`。

本命令只补齐既有 `cf_library_storage` 合同，不搬移对象、不修改库 UUID。
扫描 `Repo ∪ RepoTrash ∪ GarbageRepos`，跳过 `VirtualRepo`；库路由只取
`RepoStorageId`，不读取、修改或删除旧表。物理对象健康、真实读写与 fsck 需要另行验收。

## 命令

连接凭据沿用 `CF_V2_DB_HOST`、`CF_V2_DB_PORT`（默认 3306）、`CF_V2_DB_USER`、
`CF_V2_DB_PASSWORD`、`CF_V2_DB_NAME`。目标必须为当前 Seafile 数据库，演练使用副本。

```sh
python -m cloudfile_ext.v2 storage-reconcile \
  --seafile-conf /shared/seafile/conf/seafile.conf \
  --seafile-data /shared/seafile/seafile-data \
  --dry-run --batch-size 500
```

默认是 `--dry-run`；`--apply` 显式登记。`--batch-size` 范围为 1–2000。
`--repo-id UUID` 可定向检查。输出是单个 JSON，不附加成功提示文本：

```json
{"mode":"dry-run","summary":{"AUTO_LOCAL":1,"NATIVE":1,"ORPHAN_DIRECTORY":0},"items":[{"repo_id":"00000000-0000-4000-8000-000000000001","status":"NATIVE","storage_id":null,"category":"NATIVE","repo_key":"native-00000000-0000-4000-8000-000000000001","state":"active"},{"repo_id":"00000000-0000-4000-8000-000000000002","status":"AUTO_LOCAL","storage_id":"auto-local:old-library","category":"AUTO_LOCAL","repo_key":"old-library","state":"active"}],"orphan_directories":[]}
```

- 无原生路由：`NATIVE`，登记 `native-<uuid>`。
- `auto-local:<key>`：`AUTO_LOCAL`，检查合法 key、真实目录及至少一个对象类型的库目录。
- 本地存储类三个后端均指向原生 `seafile-data`：`NATIVE_CLASS_PINNED`，仅报告。
- 已登记且路由、key、生命周期一致：`REGISTERED`，不改动。
- 异常或不支持的存储类：`BLOCKED`，逐条附 `reason`。目录未被任何路由引用时为
  `ORPHAN_DIRECTORY`，不登记、不删除。虚拟库为 `VIRTUAL_REPO`，不登记。

正常退出 0；存在 `BLOCKED` 时退出 2；数据库、配置文件访问等执行错误退出 1，仍输出 JSON。
存在于 `Repo` 或 `RepoTrash` 的库登记为 `active`；仅在 `GarbageRepos` 的库为 `retired`。

预检与 apply 都允许幂等执行与 Server `cloudfile-v2.sql` 完全一致的
`CREATE TABLE IF NOT EXISTS cf_library_storage`，并验证既有结构；不会创建其他表。
因此 dry-run 不写登记记录，但不是完全只读的数据库操作，需要该表的建表与临时表权限。

## 显式解除原生默认类固定路由

先检查报告，只有运维明确选定的原生类才传 `--normalize-native-class ID`；可重复传入多个 ID。
`--dry-run` 保持 `NATIVE_CLASS_PINNED` 分类。应用时删除该库的 `RepoStorageId` 行与登记
`native-<uuid>` 位于同一个事务，任一步失败均回滚；S3、其他本地路径及混合后端不能转换。

```sh
python -m cloudfile_ext.v2 storage-reconcile \
  --seafile-conf /shared/seafile/conf/seafile.conf \
  --seafile-data /shared/seafile/seafile-data \
  --apply --normalize-native-class legacy-default
```

切换为 filesystem 前必须处理仍然存在的 `NATIVE_CLASS_PINNED`；普通 `--apply` 和启动时
reconcile 均不会自动解除固定路由。配置读取优先使用 `[cloudfile_v2] auto_local_root`；
没有该项时，从存储类 JSON 中唯一的 `auto-local` 本地模板读取旧存储根。
相对 `storage_classes_file` 与原生 Server 一样相对于 `seafile.conf` 的目录解析；
`CF_STORAGE_CLASSES_JSON` 与原生 Server 一样优先于文件。

每库一个事务，写入用 `INSERT ... SELECT` 复核原生生命周期、路由和虚拟库事实。
现有记录和唯一键冲突不会被覆盖。已成功的其他库保留登记，命令可幂等重试。
启动／Hub 管理入口使用相同规则，只自动处理 `NATIVE` 和 `AUTO_LOCAL`，其余记录返回报告并记日志。

## 本地回归

使用独立的临时 MariaDB 11.4，容器只对本机开放端口，密码仅为测试夹具：

```sh
docker run --detach --name cf-storage-reconcile-test-20261020 \
  -e MARIADB_ROOT_PASSWORD=storage-test-only -p 127.0.0.1:13319:3306 mariadb:11.4
CF_STORAGE_TEST_MYSQL_PORT=13319 python3 -m unittest \
  cloudfile_ext.v2.tests.test_storage_reconcile \
  cloudfile_ext.v2.tests.test_native_discovery -v
docker rm --force cf-storage-reconcile-test-20261020
```

实测结果：`Ran 25 tests ... OK`，其中 16 项使用独立 MariaDB 模式验证；包括逐类分类、
CLI 默认预检/显式应用、幂等、并发同库登记、唯一键冲突、规范化失败回滚、Garbage 生命周期、
Virtual 跳过、旧表不读取以及 Hub 运行时共用规则。

未覆盖：生产或 DEV 数据副本的 1,407 自动库 / 63 默认库计数核对；真实 Server 上传、下载、
历史版本、恢复、GC、fsck；三仓镜像完整构建。未执行 DEV 或生产部署。
