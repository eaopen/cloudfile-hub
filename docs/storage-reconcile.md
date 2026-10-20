# 原生存储登记预检

Hub 基线：`ee732e74ce02f184586e1313b489e2198dbc15fe`。

命令只补齐既有 `cf_library_storage` 合同，不搬移对象、不修改库 UUID。数据来自
`Repo ∪ RepoTrash ∪ GarbageRepos`、`VirtualRepo`、`RepoStorageId`、Seafile 配置与物理目录；
旧存储 key 表不读取、不修改、不删除。对象健康与实际读写需要单独验收。

## 命令与只读合同

连接凭据使用 `CF_V2_DB_HOST`、`CF_V2_DB_PORT`（默认 3306）、`CF_V2_DB_USER`、
`CF_V2_DB_PASSWORD`、`CF_V2_DB_NAME`，目标为当前 Seafile 数据库。

```sh
python -m cloudfile_ext.v2 storage-reconcile \
  --seafile-conf /shared/seafile/conf/seafile.conf \
  --seafile-data /shared/seafile/seafile-data \
  --dry-run --batch-size 500
```

默认 `--dry-run` **严格只读**：数据库只执行 SELECT/SHOW，不创建普通表、临时表或登记行。
结构校验仅读取 information_schema 和 SHOW CREATE TABLE，SELECT 权限即可运行。
登记表不存在时独立报告 `SCHEMA_MISSING`，并把登记关系视为空集继续分类；这不是业务 BLOCKED。
不会创建数据库或原生表。原生五张来源表不完整时在任何建表前拒绝。

```json
{"mode":"dry-run","schema":{"status":"SCHEMA_MISSING"},"summary":{"NATIVE":1,"ORPHAN_DIRECTORY":0,"SCHEMA_MISSING":1},"items":[{"repo_id":"00000000-0000-4000-8000-000000000001","status":"NATIVE","storage_id":null,"category":"NATIVE","repo_key":"native-00000000-0000-4000-8000-000000000001","state":"active"}],"orphan_directories":[]}
```

只有 `--apply` 可幂等创建与 Server `cloudfile-v2.sql` 完全一致的登记表并写登记行。
`--batch-size` 范围 1–2000；`--repo-id UUID` 可定向检查。正常退出 0；有业务 `BLOCKED` 时退出 2；
数据库/文件访问、结构漂移等执行错误退出 1，均输出单个 JSON。`SCHEMA_MISSING`、`STATE_DRIFT`
单独存在时不导致非零退出。旧 install/reconcile 命令拒绝 storage 专用模式参数，避免
误传 `--dry-run` 后仍执行变更。

## 分类与生命周期

- 无原生路由：`NATIVE`，新登记 key 为 `native-<uuid>`。存在但 storage_id 为 NULL 的路由行为
  `BLOCKED: INVALID_STORAGE_ROUTE`，不会误认作没有路由。
- `auto-local:<key>`：`AUTO_LOCAL`，要求 key 合法，存储根及祖先、key/storage/type/repo
  目录链没有符号链接，且至少一个对象类型存在真实库目录。
- 三个 fs 后端均指向真实原生 `seafile-data` 的存储类：`NATIVE_CLASS_PINNED`，默认只报告。
  CE 标准原生路径符号链接可解析到相同真实原生目录；managed auto root 仍禁止符号链接。
- 已登记且 key/路由/owner 一致：`REGISTERED`。既有 reserved 与推算 active 兼容，不阻断也不改状态。
- 仅生命周期 active/retired 不一致：`STATE_DRIFT`，返回实际 `state` 和推算 `expected_state`，
  只报告，不 BLOCKED，也不自动覆盖。例：已 retired 但库仍在 RepoTrash 中，保持 retired，报告预期 active。
- key、路由或 owner 冲突、非法/缺失/符号链接目录、不支持的后端：`BLOCKED`，逐条附 `reason`。
  虚拟库为 `VIRTUAL_REPO`，不登记。未被任何原生路由引用的目录为 `ORPHAN_DIRECTORY`，不登记、不删除；
  引用检查读取全部 RepoStorageId，不限于扫描批次。

仅新登记记录按原生事实推算状态：Repo 或 RepoTrash 中为 active，仅 GarbageRepos 中为 retired。
RepoTrash 与 GarbageRepos 重叠时优先 active。既有登记的状态保持不变。

## 显式解除原生默认类固定路由

只有运维明确选择的类才传 `--normalize-native-class ID`，可重复指定。dry-run 仍报告 pinned；
普通 apply 和运行时 reconcile 不解除固定路由。显式规范化在每库同一事务中删除原生路由、登记
`native-<uuid>`，失败全部回滚。S3、其他本地路径与混合后端不可转换。

```sh
python -m cloudfile_ext.v2 storage-reconcile \
  --seafile-conf /shared/seafile/conf/seafile.conf \
  --seafile-data /shared/seafile/seafile-data \
  --apply --normalize-native-class legacy-default
```

切换 filesystem 前处理业务 BLOCKED 与仍然存在的 NATIVE_CLASS_PINNED；缺登记表的只读预检可先通过，
然后显式 apply 建表、登记。配置优先 `[cloudfile_v2] auto_local_root`，否则读取存储类 JSON 的
唯一 auto-local/fs 模板。相对 storage_classes_file 与原生 Server 一样相对于 conf 目录；
CF_STORAGE_CLASSES_JSON 优先于文件。legacy install/reconcile 从现有 Seafile 环境变量和标准目录检测配置。

每库一个事务；INSERT SELECT 在写时复核原生事实与字节精确路由，唯一键冲突不会覆盖其他登记。
已成功的其他库保留，可幂等重试。Hub runtime 共用规则，只自动处理 NATIVE/AUTO_LOCAL，其他项仅报告。

## 版本证据与验证

Docker `origin/dev a7e8c2bf1e4e7630dfa2e54427c1c03d98ad667e` 的
`deploy/compose/docker-compose.yml:27` 明确使用 `mariadb:11.4`；这是部署配方证据。
远端设备未连接，不能据此宣称远端当前实际运行版本已核实。

隔离测试服务器实际 `SELECT VERSION()`：

- `11.4.13-MariaDB-ubu2404`：与部署配方相同 11.4 系列。
- `10.11.19-MariaDB-ubu2204`：追加兼容验证，不称为 DEV 同版。

```sh
CF_STORAGE_TEST_MYSQL_PORT=13319 python3 -m unittest \
  cloudfile_ext.v2.tests.test_storage_reconcile cloudfile_ext.v2.tests.test_native_discovery -v
CF_STORAGE_TEST_MYSQL_PORT=13320 python3 -m unittest \
  cloudfile_ext.v2.tests.test_storage_reconcile cloudfile_ext.v2.tests.test_native_discovery -v
```

两版本均 `Ran 39 tests ... OK`，后续新增结构变更只读拒绝用例在两版本各单独通过，
并对用户“native retired 但仍在 Trash”的精确场景在两版本追加定向通过。
包含 SELECT-only 账户在 `START TRANSACTION READ ONLY` 下的有表/缺表双场景、缺表只读分类后
apply 安装、reserved 兼容、STATE_DRIFT 保持、原生 symlink 布局、写时路由复核、并发唯一键、
规范化回滚、Trash/Garbage、Virtual、全局 ORPHAN 与旧表哨兵不变。

实现阶段两轮元数据检查失败分别来自 index_name 默认排序顺序与 MariaDB 对 SELECT-only 用户隐藏
CHECK_CONSTRAINTS；现分别用确定排序与 SHOW CREATE 纯解析修正，最终回归通过。
原生表结构漂移（约束、唯一键、排序规则、列默认值）只读拒绝，不改表。

未覆盖：远端运行版本实测、真实 Server 上传/下载/历史/恢复/GC/fsck、完整三仓镜像验收。
1,407/63 个真实库数量核对按用户最新要求留至发布后；本轮不等待副本，未部署 DEV 或生产。

独立的 11 库 + 1 孤儿目录、batch_size=2 CLI 合成验收也在两版本通过：缺登记表预检报告
SCHEMA_MISSING 且确实未建表；有表预检 NATIVE=3/AUTO_LOCAL=3/PINNED=1/BLOCKED=3/Virtual=1/Orphan=1；
显式 apply/normalize 与重放 REGISTERED=7/BLOCKED=3/Virtual=1/Orphan=1，重放无写入。
预置 BLOCKED 为 S3/非法 key/既有登记冲突，旧表哨兵不变；全部数据为合成数据。
