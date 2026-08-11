<!-- generated-by: gsd-doc-writer -->
# 扩展注册中心

> 用途：定义 Hub 新能力如何注册、选择、调用和退出，避免新增上游修改。
> 适用版本：Seafile CE 14.x。
> 状态：已完成（注册中心及 provider 单元测试通过，2026-08-11）。

## 概览

`cloudfile_ext.registry.Registry` 是进程内注册中心，不是可热插拔的通用插件平台。所有注册发生在 `CloudFileConfig.ready()`；请求期只做查找和分派；`seal()` 后注册会失败。

## 链式扩展点

链式扩展点允许多个能力共同参与：

| 扩展点 | 注册方法 | 调用语义 | 当前使用者 |
|---|---|---|---|
| URL | `register_urls()` | 合并到 `cloudfile_ext.urls` | 所有带 API/页面的能力 |
| 菜单 | `register_menu()` | 前端读取并再次按 feature 开关过滤 | ACL、SSO、外部源 |
| 权限 | `register_permission_check()` | 顺序传递权限结果，只能收紧 | 目录 ACL |
| 文件操作 | `register_file_op_hook(phase, fn)` | pre 可拒绝；post 异常只记录 | 当前无已注册实现 |
| 搜索索引器 | `register_search_indexer()` | 每个索引器都接收文档 | 当前索引任务直接由 worker 调用，未注册链成员 |
| 外部源 | `register_external_source_provider()` | 按 source type 共存 | `local-path` |
| 周期任务 | `register_periodic_task()` | 单进程串行调度 | ACL 同步、SSO 同步、Meilisearch、外部源扫描 |

`post` 文件操作钩子吞掉并记录异常，避免观察型审计/索引破坏已经完成的写操作；`pre` 异常会阻止操作。

## 可互换 Provider

Provider 回答“同一职责由哪个实现处理”，每种 kind 同时只选择一个：

```text
kind: search             -> CF_PROVIDER_SEARCH
kind: acl_rule_source    -> CF_PROVIDER_ACL_RULE_SOURCE
kind: sso_directory      -> CF_PROVIDER_SSO_DIRECTORY
```

空值表示不选择 CloudFile provider，通常回到 CE 原生行为。非空名称必须与已注册名称完全一致；配置了不存在的名称会抛出 `UnknownProvider`，不会静默回退。

| Kind | 已注册名称 | 默认行为 |
|---|---|---|
| `search` | 条件注册 `meilisearch` | 空值走原生 SeaSearch/Elasticsearch |
| `acl_rule_source` | `local-db` | 未选时由 ACL 模块使用本地数据库；`external-service` 尚未实现 |
| `sso_directory` | `static`、`external-service` | 未选时只启用 CE 登录配置，不做组织同步 |

## 添加能力

新能力应把导入放在 `register()` 内部，先检查开关，再登记贡献：

```python
def register(registry):
    from cloudfile_ext.features import is_enabled
    if not is_enabled('CF_ENABLE_EXAMPLE'):
        return

    from django.urls import path
    from cloudfile_ext.example.views import ExampleView

    registry.register_urls([
        path('api/v2.1/cloudfile/example/', ExampleView.as_view()),
    ])
```

还需在 `CloudFileConfig.ready()` 的模块列表中加入该包，并为“开关关闭无贡献”添加测试。若能力只是同一职责的新实现，调用 `register_provider()`，不要增加新的中央分发表。

## 后台任务

`python manage.py cf_worker` 读取注册中心的 `periodic_tasks`。任务在单进程中串行运行；单个失败只记录日志，下个周期重试。`--once` 会把每个已注册任务执行一次后退出；没有任务时命令直接退出。

当前任务可能包括：

- `acl-rule-sync`：固定 300 秒；本地数据库 source 为 no-op。
- SSO 全量同步：默认 600 秒，最小 60 秒。
- Meilisearch 增量索引：默认 60 秒，最小 15 秒。
- 外部源扫描：仅在外部源和 Meilisearch 同时启用时注册，默认 60 秒。

## 诊断

已认证用户可请求 `GET /api/v2.1/cloudfile/features/`，查看功能开关、各 kind 的 selected/available provider 和菜单项。该端点只用于诊断和展示；后端能力仍必须自行做开关、身份和权限校验。
