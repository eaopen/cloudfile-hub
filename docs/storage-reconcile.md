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

## 安全边界复审（2026-10-20）

复审修复三处边界：存储根任何祖先组件为符号链接时拒绝；存在但值为 NULL 的
`RepoStorageId` 为 `BLOCKED: INVALID_STORAGE_ROUTE`，不当作无路由；写入复核使用真实
路由行不存在或字节精确匹配，避免数据库默认排序规则将不同大小写视为同一路由。
规范化删除路由也使用字节精确匹配。旧 `reconcile` 等命令拒绝 storage 专用模式参数，
防止误传 `--dry-run` 后仍执行变更。建表前必须验证五张原生来源表完整，错误数据库
以 `NATIVE_SEAFILE_DATABASE_NOT_CONNECTED` 拒绝且不创建登记表。

新增 10 项针对性回归，并复验 4 项受影响的并发/规范化/Hub 入口用例；分三次执行：
`Ran 11 tests ... OK`、`Ran 3 tests ... OK`、`Ran 1 test ... OK`（其中干净登记表预检重复验证一次）。
覆盖根祖先、storage/type/repo 目录链符号链接、NULL 路由、写时大小写路由变化、
Trash 与 Garbage 重叠 active、批次外全局路由对 ORPHAN 的保护，以及预检前不存在登记表。

另外使用独立临时数据库运行 11 个合成库、1 个孤儿目录的 CLI 验收，batch_size=2：

```json
{"dry_run":{"NATIVE":3,"AUTO_LOCAL":3,"NATIVE_CLASS_PINNED":1,"BLOCKED":3,"VIRTUAL_REPO":1,"ORPHAN_DIRECTORY":1},"apply":{"REGISTERED":7,"BLOCKED":3,"VIRTUAL_REPO":1,"ORPHAN_DIRECTORY":1},"replay":{"REGISTERED":7,"BLOCKED":3,"VIRTUAL_REPO":1,"ORPHAN_DIRECTORY":1},"result":"PASS"}
```

三个预置 BLOCKED 分别为 S3、非法 key、登记冲突。显式规范化后新增 7 条登记，重放无写入，
垃圾库 retired、Trash+Garbage 重叠库 active，旧表哨兵保持不变。数据完全合成，不作为
1,407/63 个真实库数量核对证据；该真实数据核对按用户最新要求留至发布后验收。
