# 旧索引完整性对账（legacy 兼容索引）

`cf_search_reconcile` 是 `cf_search_backfill_directories` 的**只读**对照命令。
补索引回答“我写了多少文档”，本命令回答“现在这个资料库到底有多少原生条目在索引里有对应文档”。

背景：2026-10-06 对资料库 `etech01`（`4f09f8a8-40c0-4ded-bec9-6c42691034f5`）做过一次全量补索引，
当时记录 862,177 个原生文件对应 862,233 条文件文档、899,804 条总文档，但那是**一次性抽样**，
没有可重复的复核手段。本命令把“覆盖率”变成一个可重复、可加门槛的标准动作。

## 范围与明确限制

- 只检查 **legacy 兼容索引** `cloudfile_files`（`cloudfile_ext/search/backends/meilisearch.py` 的 `INDEX_NAME`）。
- 它**不能**说明新的 `search.resources` 查询路径是否完整；两者是独立链路，本命令对后者一言不发。
- **全程只读**：不调用 `ensure_index()`，不写文档、不改设置、不删文档、不建索引。
- 只统计“文档 id 是否存在”。不读文件正文，不做权限矩阵，不校验 `size`/`mtime`/`tags` 是否与原生一致。
- 原生遍历沿用既有资料库所有者身份，与补索引相同；不是某个终端用户的视角。
- 不启用定时任务；一次运行有界（`--max-pages`/`--max-stale-checks`），可反复续跑。

## 命令

```sh
S=/opt/seafile/seafile-server-latest
cd $S/seahub
python3 manage.py cf_search_reconcile \
  --repo-id 4f09f8a8-40c0-4ded-bec9-6c42691034f5 \
  --checkpoint /shared/seafile/search-file-repair/reconcile-etech01.json \
  --max-pages 100
```

重复运行同一条命令（同一检查点），直到报告里 `complete=true`。

### 参数

- `--repo-id`：必填，资料库 UUID。
- `--checkpoint`：可选但推荐。检查点文件（权限 0600，原子替换）与 `<checkpoint>.lock` 独占 `flock`。
  两个运维进程不能同时推进同一检查点，第二个直接报 `This checkpoint is already in use.`。
- `--max-pages`：1..100，默认 10。每页固定读取 100 个直接子项（多读 1 个判断是否还有下一页），
  即一次运行最多访问这么多原生页。到达上限仍有 `pending` 时 `complete=false`。
- `--threshold`：0..1，默认 `0.999`。见下节。
- `--allow-incomplete`：遍历未走完时不因“未完成”而失败（仅抑制未完成退出码，不抑制门槛）。
- `--stale`：打开反向检查（默认关闭），见“反向检查”一节。
- `--max-stale-checks`：1..100000，默认 200。反向检查最多翻看多少条索引文档。

## JSON 报告

命令向 stdout 只输出**一行 JSON**（不打印凭据、游标内部结构或文档正文；缺失路径样例只有路径本身）：

```json
{
  "repo_id": "4f09f8a8-40c0-4ded-bec9-6c42691034f5",
  "head": "<固定提交 head_cmmt_id>",
  "native_files": 862177,
  "native_dirs": 37571,
  "indexed_files": 862233,
  "indexed_dirs": 37571,
  "missing_files": 0,
  "missing_dirs": 0,
  "coverage_ratio": 1.0,
  "sample_missing": [{"path": "/some/gone.txt", "object_type": "file"}],
  "pages": 8622,
  "complete": true
}
```

字段：

- `native_files` / `native_dirs`：本次已遍历到的原生条目数（不是资料库宣称的总数）。
- `indexed_files` / `indexed_dirs`：其中在索引里找得到文档的条目数。
- `missing_files` / `missing_dirs`：找不到文档的条目数；恒有
  `indexed_files + missing_files = native_files`（目录同理）。
- `coverage_ratio`：**文件覆盖率** `indexed_files / native_files`，保留 6 位小数；
  `native_files = 0` 时定义为 `1.0`。它是门槛的判据。
- `sample_missing`：最多 20 条缺失样例，元素为 `{"path", "object_type"}`；
  完整缺失集只以计数呈现，避免报告体积随缺口规模膨胀。
- `pages`：已遍历的原生页数。
- `complete`：遍历是否走完（`pending` 栈为空）。
- `stale`：仅在 `--stale` 时出现的额外字段，见下节。

## threshold 语义与退出码

- 文件覆盖率 `coverage_ratio < --threshold` **且遍历已完成** → 退出码 `3`。
- 遍历未完成（`complete=false`）且未给 `--allow-incomplete` → 退出码 `2`。
- 未完成时**不**评估门槛：此时 `coverage_ratio` 只覆盖已走到的部分树，不代表整库覆盖率。
- 其他错误（参数非法、检查点损坏、head 变化、索引请求失败）走 Django `CommandError`，退出码 1。
- 无论是否失败，JSON 报告都先打印，便于定位门槛失败的原因。

默认 `0.999` 是“标准门槛”而不是“容忍部分补索引”：历史上少量陈旧文档会带来一点差距，
而真正的回退会把比率推得很低，所以门槛宁可严格。

## 批量存在性与版本探测

每个原生页的 100 个条目对应**一次**索引请求，而不是每条路径一次：

```
POST /indexes/cloudfile_files/documents/fetch
{"ids": ["<repo_id>-<sha1(path)>", ...], "limit": 100}
```

- 文档 id 与补索引完全一致：`cloudfile_ext/search/ops.py::doc_id`，即 `<repo_id>-<sha1(path)>`。
- 启动时先用空 `ids` 探针（`{"ids": [], "limit": 1}`）验证该端点存在且返回 `{"results": [...]}` 形状；
  失败（端点不存在、旧版本、响应畸形）则整体回退到逐文档
  `GET /indexes/cloudfile_files/documents/<id>`（404 视为缺失，正常回答而非错误）。
- 正常响应只返回命中的 id，`total` 是命中数。若响应被截断（`total` 大于返回条数），
  只对被截断、未返回的那些 id 走逐文档回退，绝不把它们误报为缺失。
- 在 v1.53.2 上已实测：`documents/fetch` 支持 `ids`+`limit`，也支持 `filter`+`offset`+`limit`+`fields`。

## 检查点、head 固定与可续跑

- 启动时固定资料库 `head_cmmt_id`，之后所有分页都读
  `list_dir_by_commit_and_path(repo_id, head, ...)`；`assert_current()` 在每页前后复核 head，
  变化即报 `Library changed; restart with a new checkpoint.`。
- 检查点保存 `repo_id`、`head`、待处理 `pending` 栈、`pages`/`directories`/`files`，
  以及 `indexed_*`/`missing_*`/`sample_missing` 计数器；原子替换、权限 0600。
- 恢复时严格校验：计数器为非负整数、`indexed + missing == 已遍历`（文件与目录各自成立）、
  库与 head 一致、`pending` 结构合法。任一项不合法都报
  `Checkpoint is invalid or library changed; use a new checkpoint.`，不猜测进度。
- 存在性在每页回调内**同步**判定，页面返回后该页每个条目都已有结论，检查点计数器因此
  永远不会领先于实际探测；中断重跑只会重复探测同一批只读请求（幂等）。

## 反向检查（`--stale`）

正向检查回答“原生有的、索引里有没有”；反向检查回答“索引里有的、原生还在不在”。

- 用 `filter: repo_id = "<repo_id>"` 分页 `documents/fetch`，每次只取 `fields` 里的
  `id`/`path`/`object_type`，按 `--max-stale-checks` 封顶翻看。
- 对每条文档用原生接口判断路径类型是否仍存在（目录 `get_dir_id_by_path`，
  文件 `get_file_id_by_path`）；不存在即记为 stale。
- 报告增加 `"stale": {"checked": N, "stale": [{"path", "object_type"}, ...]}`。
- 默认关闭；它按路径做原生 RPC，所以必须显式开启并给上限，避免变成无界扫描。

## 验证

本地回归（`cloudfile_ext/search/tests/test_search_reconcile.py`）：

- 遍历对原生文件/目录、命中、缺失的计数正确，`sample_missing` 只收缺失项；
- 每访问一页只发生一次批量 `documents/fetch`，无逐文档 HTTP 调用；探针为空 `ids` 调用；
- 批次被截断时只对未返回的 id 走逐文档回退，缺失计数不被误报；
- 端点不可用时整体回退逐文档并提示；
- 覆盖率低于 `--threshold` 与遍历未完成都非零退出，`--allow-incomplete` 抑制未完成退出；
- 检查点 0600、原子、可续跑，损坏/跨 head 的检查点被拒绝；
- 运行中 head 变化立即中止且不推进检查点；同一检查点被占用时拒绝启动；
- `--stale` 报告失效路径且遵守 `--max-stale-checks` 边界；默认关闭；
- 非法参数在触碰资料库与索引之前被拒绝。

代码测试不等于生产对账已完成。生产验收应看：真实运行的 `complete=true` 与最终
`coverage_ratio`，并与既有记录（862,233 / 862,177）比对；少量差异来自历史陈旧文档，
属预期，不应强行对齐。
