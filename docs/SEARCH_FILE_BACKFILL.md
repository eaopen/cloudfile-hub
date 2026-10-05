# 有界搜索的文件级补索引（legacy 兼容索引）

修改原因：`cloudfile_files` 这个旧 Meili 索引只由 seafevents 的 `Activity` 流驱动（`cloudfile_ext/search/indexer.py`）。历史上某资料库 862,177 个原生文件只对应约 140,074 行 Activity，索引覆盖率约 47.7%，且只有目录有补索引入口，文件没有。结果是旧索引里大量既有文件搜不到，这不是前端过滤造成的。

本文件描述**文件级**补索引。目录补索引见 [SEARCH_DIRECTORY_REPAIR.md](SEARCH_DIRECTORY_REPAIR.md)；两者复用的算法与检查点语义相同。

## 范围与明确限制

- 本命令只修复**legacy 兼容索引** `cloudfile_files`。它让旧查询路径恢复对既有文件的覆盖。
- 它**不会**启用新的 `search.resources` 路径，也不替代缺失的字节提交事件桥（byte-commit event bridge）。新路径要可用仍需该桥接落地；补索引不是它的替代品。
- 只写元数据：名称、路径、`object_type`、大小、mtime、祖先目录和标签。不抓取文件正文，也不修复正文检索质量。
- 不启用任何定时任务，不在用户搜索请求里扫描资料库；补索引期间结果逐批可见，不宣称原子全量发布。
- 命令不删除已有索引文档；旧路径的候选由查询侧实时存在性/权限检查排除。

## 为什么不抓正文（`max_bytes=0`）

文件文档通过

```python
_build_document(repo_id, path, '', mtime, max_bytes=0, object_type='file')
```

构建，`max_bytes=0` 是硬要求：

- 每页 100 个直接子项。若按增量索引的上限（`CF_SEARCH_INDEX_TEXT_MAX_BYTES`，默认 1 MiB）抓正文，100 个文档最坏 100 MiB，超过 Meilisearch 单次写入载荷上限，写入会被拒或长时间挂起。
- 写入失败/挂起时不推进检查点，于是每次重跑都在同一页失败，补索引**永远卡在起始页**，看起来像死循环而没有进度。
- `op_user` 传空串：补索引代表系统，不代表任何用户，与 cf-worker 后台任务一致。

正文索引仍由 Activity 增量链负责；本命令只保证“文件至少存在一条可检索的元数据文档”。

## 运维命令

先部署包含本次修改的 Hub/worker，确认已有 Meilisearch provider（`CF_PROVIDER_SEARCH=meilisearch`）和索引配置。然后对每个资料库执行：

```sh
# 1) 目录（默认行为，未改动；可先补完目录）
python manage.py cf_search_backfill_directories \
  --repo-id <资料库UUID> \
  --checkpoint /持久化运维目录/search-directory-cursor.json \
  --kinds dir \
  --max-pages 10

# 2) 文件级补索引（legacy 索引的主要缺口）
python manage.py cf_search_backfill_directories \
  --repo-id <资料库UUID> \
  --checkpoint /持久化运维目录/search-file-cursor.json \
  --kinds file \
  --max-pages 10 \
  --flush-docs 500

# 3) 或者一次补齐目录和文件
python manage.py cf_search_backfill_directories \
  --repo-id <资料库UUID> \
  --checkpoint /持久化运维目录/search-all-cursor.json \
  --kinds all \
  --max-pages 10 \
  --flush-docs 500
```

相同命令逐批重复运行，直到输出 `complete=True`：

```
pages=<页数> directories=<目录文档数> files=<文件文档数> complete=<True/False>
```

参数语义：

- `--kinds dir|file|all`，默认 `dir`（保持原有行为）。非法值由 argparse 拒绝，直接调用 `handle` 时由命令再次校验。
  - `dir`：只写目录文档；`file`：只写文件文档；`all`：两者都写。
  - `--kinds file` **仍然会遍历整个目录树**（否则子目录里的文件根本到不了），只是不为目录构建文档、不写入目录文档。栈里始终只有目录。
- `--max-pages` 1..100，默认 10。每页固定读取 100 个直接子项（多读 1 个用于判断是否还有下一页）。
- `--flush-docs` 1..2000，默认 500。攒够这么多文档才向 Meilisearch 写一次；语义与耐久性规则见下一节。非法值报 `flush-docs must be between 1 and 2000.`，且在读取资料库之前就被拒绝。
- `--checkpoint` 建议按 kind 分开。检查点必须落在持久化目录，权限 0600；同一检查点加独占 `flock`，不允许两个运维进程并行推进。

## 写入批量化与耐久性（`--flush-docs`）

目录密集的资料库实测 `/` 为 28 目录 + 18 文件、`/..临时存档` 为 58 目录 + 3 文件，大多数原生页只有几个文档。按“每页一次 Meili PUT + 等待异步任务”推进时实测约 5.5 秒/页、约 70 文档/分钟，45 万文件要跑约 4.5 天，而瓶颈几乎全在写入等待，不在原生 list RPC。因此命令把多页文档攒进内存缓冲，达到阈值才写一次：

- `advance_page` 仍逐页回调写文档，但回调只把文档追加进缓冲并计数。只有 `len(buffer) >= --flush-docs` 时才做一次 PUT，并轮询该 Meili task 到 `succeeded`（30 秒上限）。
- 内存上界就是阈值本身：缓冲最多为 `N + 99` 个**仅元数据**文档（一页最多 100 条），不随资料库规模增长；文件文档仍以 `max_bytes=0` 构建，不会把正文带进内存或 Meili 载荷。
- 页数与文档数仍逐页累计，所以输出和检查点里的 `pages=%d directories=%d files=%d` 计数不因批量而改变。

耐久性规则（不可回退）：**磁盘上的检查点只能描述已经在 Meilisearch 里持久化的进度。**

- 检查点只在一次 flush 成功之后写盘（仍是先写临时文件再 `os.replace` 的原子替换），以及整轮结束前的最后一次 flush 之后再写一次。
- 绝不把“已遍历页的文档还在缓冲、尚未写入”的进度写进检查点；否则重跑会从检查点之后开始，这批文档成为永久缺口。
- PUT 被拒、task `failed`、task 在 30 秒内仍是 `enqueued/processing`、或库 head 变化时：缓冲中的文档不写检查点，上一版磁盘检查点保持原样，命令以非零退出（`Index write failed; checkpoint was not advanced.` / `Index write pending; rerun the same checkpoint to retry safely.` / `Library changed; restart with a new checkpoint.`）。重跑同一检查点会重读同样的页，文档 id 稳定，幂等覆盖。

## 标签预加载与快照语义

实测 `_fetch_tags(repo_id, path)` 单次约 25.65 ms（同期 `get_file_id_by_path` 3.94 ms、`get_file_size` 0.77 ms、`_ancestor_dirs` 约 0 ms），而全站标签表规模极小（`tags_fileuuidmap` 63 行、`tags_filetag` 33 行、`tags_tags` 27 行）。于是“每份文档一次标签查询”成了补索引的唯一瓶颈，吞吐被压到约 20 文件/秒。

命令现在在资料库/head/索引校验通过之后、进入分页循环之前，用 `preload_tags(repo_id)` 一次性加载本次运行的标签快照：

- **有界查询**：先取该资料库的 `FileUUIDMap` 行，再分别按 uuid 取 `FileTags`（文件，join `repo_tag`）与 `FileTag`（目录，join `tag`），共 3 条查询覆盖整库全部路径，不再随文档数增长。虚拟资料库按 `FileUUIDMapManager` 的同一套 origin repo / origin path 改写取行，保证与逐路径查询命中同一批绑定。
- **取值一致**：返回两个按规范化路径（`seahub.utils.normalize_file_path`，即 parent_path + filename）索引的字典（文件标签、目录标签）；文件保留查询顺序，目录去重后排序，`is_dir` 拆分与 `_fetch_tags` / `_fetch_directory_tags` 完全相同。未打标签的路径不在字典里，取 `[]`。
- **构建入口**：`_build_document(..., tags=...)` 新增可选关键字，传入时直接使用快照；`tags=None` 时仍走原来的逐路径查询，行为逐字不变，增量索引链完全不受影响。
- **快照语义**：映射只反映预加载那一刻的标签状态。长时间运行期间新增/删除的标签不会回溯到本次已写入的文档，这些变更由既有的增量标签扇出负责，补索引不追赶它们；重跑一次补索引即可刷新快照。
- **失败回退**：预加载查询失败时命令记录告警并退回逐路径查询（即改动前的行为），不会把文档 `tags` 静默写成空。该回退路径同时保证 `tags=None` 的旧语义始终可用。

改动只落在补索引路径上；`cloudfile_ext/search/backfill.py` 仍然只 import `stat`，纯算法部分保持 Django-free。

## 固定 head 与断点续跑语义

- **固定 head**：命令启动时记录资料库 `head_cmmt_id`，之后所有分页读取都用 `list_dir_by_commit_and_path(repo_id, head, ...)`。若期间 head 变化，`assert_current()` 抛错，命令拒绝继续，必须换新检查点重跑。要求补索引期间库内容稳定。
- **检查点内容**：只保存 `repo_id`、固定 `head`、待处理路径/偏移栈 `pending`、以及 `pages`/`directories`/`files` 三个计数器。绝不保存凭据。
- **严格校验**：恢复时校验三个计数器都是非负整数、库与 head 一致、`pending` 结构合法（绝对路径、无 `.`/`..`、无 `//`、UTF-8 ≤4096 字节、offset 范围、栈深 ≤10000）。任一项不合法（含缺少 `files`）都报 `Checkpoint is invalid or library changed; use a new checkpoint.`，**忽略旧格式检查点，不猜测进度**。
- **只在写入成功后推进**：文档先攒够 `--flush-docs` 再 `PUT`，然后轮询 Meili task 直到 `succeeded`（30 秒上限）；检查点只在这次 flush 成功之后写盘。`failed` 报“checkpoint was not advanced”，仍 `enqueued/processing` 报“Index write pending; rerun the same checkpoint to retry safely”。两种情况磁盘上的检查点都保持原位置，重跑幂等（文档 id 稳定）。
- **DFS 有界**：`pending` 是深度优先的续读栈，只有目录会被入栈，文件是叶子。文件再多也不会让内存或检查点随文件数增长。`--kinds file` 也照常入栈目录（只为走到子目录），但不会为它们写文档。宽目录用“同目录 +100 偏移”的续页表示，栈深超过 10000 抛错。

## 验证

纯算法部分 `cloudfile_ext/search/backfill.py` 只依赖 `stat`，可脱离 Django 直接跑（例如用 `importlib` 按路径加载后驱动 `advance_page`）。

本地回归覆盖：

- 默认 `kinds=('dir',)` 仍只索引目录（回归）；
- `kinds=('dir','file')` 时文件文档带 `object_type='file'`，且文件从不进入 `pending`；
- `--kinds file` 仍遍历目录以覆盖嵌套文件，但不为目录写文档；
- 文件文档用 `max_bytes=0` 构建（断言回调收到的就是 0）；
- 文件文档构建返回 `None` 时 `advance_page` 抛错且不写入；
- 若干小页（含目录与文件混合）只产生一次 Meili 写入；
- 达到 `--flush-docs` 阈值时发生 flush，且 flush 之前检查点不前进、flush 之后检查点只覆盖已持久化的页；
- 轮末剩余的文档在写最终检查点之前先 flush；
- flush 失败或长时间 pending 时，上一版磁盘检查点逐字节不变，命令以非零退出（`SystemExit` 非 0）；
- `--flush-docs` 为 0、负数、大于 2000 或非整数时报错，且不触碰资料库与索引；
- 命令 `--kinds all` 持久化 `files` 计数器、输出含 `files=`，并拒绝被破坏或缺少 `files` 的检查点；
- Meili 写入失败或异步任务长时间 pending 时都不推进检查点；
- 标签预加载：在隔离的真实 ORM（SQLite）上，`preload_tags` 的映射对文件、目录、未打标签路径、同名文件/目录与虚拟资料库都与 `_fetch_tags` / `_fetch_directory_tags` 逐路径结果一致，且整库只发 3 条 SELECT；
- 补索引运行期间不再发生任何逐路径标签查询（预加载失败以外的路径）；
- `_build_document(tags=None)` 仍调用逐路径查询，显式传入（含空列表）时不再查询。

代码测试不等于生产补索引已完成。生产验收应选一个既有文件（仅存在于原生树、不在 Activity 覆盖内）、一个目录和同名文件，在“全库 / 所在目录”分别搜索，确认文件命中且未授权对象不出现。
